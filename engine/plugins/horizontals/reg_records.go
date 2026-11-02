// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type horRegRec struct {
	name   string
	plugin *horizPlugin
}

func (h *horRegRec) Name() string {
	return h.name
}

func (h *horRegRec) check(e *et.Event) error {
	var rlabel string
	t := e.Entity.Asset.AssetType()

	// check if scope expansion is allowed
	if e.Session.Config().Rigid {
		return nil
	}

	switch t {
	case oam.AutnumRecord:
		rlabel = "registrant"
	case oam.DomainRecord:
		rlabel = "registrant_contact"
	case oam.IPNetRecord:
		rlabel = "registrant"
	default:
		return fmt.Errorf("asset type not supported: %s", t)
	}

	cr, err := h.plugin.getContactRecord(e.Session, e.Entity, rlabel)
	if err != nil {
		return nil
	}

	orgs, locs := h.plugin.lookupContactRecordOrgsAndLocations(e.Session, cr)
	if len(orgs) == 0 && len(locs) == 0 {
		return nil
	}

	switch t {
	case oam.AutnumRecord:
		h.processAutnumRecord(e, orgs, locs)
	case oam.DomainRecord:
		h.processDomainRecord(e, orgs, locs)
	case oam.IPNetRecord:
		h.processIPNetRecord(e, orgs, locs)
	}
	return nil
}

// firstInScope returns the first of the registrant's organizations, then
// locations, that is in scope, or nil.
func (h *horRegRec) firstInScope(sess et.Session, orgs, locs []*dbt.Entity) *dbt.Entity {
	for _, o := range orgs {
		if h.plugin.isEntityInScope(sess, o) {
			return o
		}
	}
	for _, loc := range locs {
		if h.plugin.isEntityInScope(sess, loc) {
			return loc
		}
	}
	return nil
}

// expand adds the registrant's organizations and locations to scope.
func (h *horRegRec) expand(sess et.Session, from *dbt.Entity, via string, orgs, locs []*dbt.Entity) {
	for _, o := range orgs {
		h.plugin.enqueueIfOutOfScope(sess, o, from, via)
	}
	for _, loc := range locs {
		h.plugin.enqueueIfOutOfScope(sess, loc, from, via)
	}
}

// declineForeign reports whether the registration record (an AutnumRecord
// or IPNetRecord) names another organization, so that what it registers must
// not be admitted and its registrant must not be expanded. Records for what
// the operator seeded are never declined.
func (h *horRegRec) declineForeign(e *et.Event) bool {
	switch v := e.Entity.Asset.(type) {
	case *oamreg.AutnumRecord:
		if support.IsSeedAsset(e.Session, &oamnet.AutonomousSystem{Number: v.Number}) {
			return false
		}
	case *oamreg.IPNetRecord:
		if support.IsSeedAsset(e.Session, &oamnet.Netblock{CIDR: v.CIDR, Type: v.Type}) {
			return false
		}
	}
	return support.DeclineForeignRegistration(e.Session, e.Entity, h.plugin.name)
}

func (h *horRegRec) processAutnumRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// check if the autnum record / registered autonomous system is in scope
	if h.plugin.isEntityInScope(e.Session, e.Entity) {
		if !h.declineForeign(e) {
			h.expand(e.Session, e.Entity, "registration record", orgs, locs)
		}
		return
	}

	match := h.firstInScope(e.Session, orgs, locs)
	if match == nil || h.declineForeign(e) {
		return
	}

	// the autonomous system should be added to the scope
	if an, valid := e.Entity.Asset.(*oamreg.AutnumRecord); valid {
		if as := h.plugin.addASNetblocksToScope(e.Session, an.Number); as != nil {
			h.plugin.addToScopeAndEnqueue(e.Session, as, match, "registrant match")
		}
	}
	h.expand(e.Session, match, "registrant match", orgs, locs)
}

func (h *horRegRec) processDomainRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// check if the domain record / registered domain name is in scope
	if h.plugin.isEntityInScope(e.Session, e.Entity) {
		h.expand(e.Session, e.Entity, "registration record", orgs, locs)
		return
	}

	match := h.firstInScope(e.Session, orgs, locs)
	if match == nil {
		return
	}

	// get the registered domain FQDN entity
	if fqdn, err := h.plugin.getRegisteredDomainEntity(e.Session, e.Entity); err == nil && fqdn != nil {
		// add the FQDN to the session scope and review it: queue the domain
		// name itself, not the registration record, so the work done only
		// for in-scope names (subdomain discovery) runs on it
		h.plugin.enqueueIfOutOfScope(e.Session, fqdn, match, "registrant match")
	}
	h.expand(e.Session, match, "registrant match", orgs, locs)
}

func (h *horRegRec) processIPNetRecord(e *et.Event, orgs []*dbt.Entity, locs []*dbt.Entity) {
	// A netblock in scope does not make its registrant the target. A block
	// can be in scope only because the target's hosts sit on it, which makes
	// the target a tenant there, not the owner. So an in-scope record expands
	// to its registrant's organizations and locations only when the block is
	// attributed to the target: an RDAP contact email on a seed domain.
	// Otherwise it is handled like an out-of-scope record below, and expands
	// only when its registrant is already known to be in scope.
	//
	// The record is stored under the range it registers, which may be larger
	// than the netblocks in scope (a /22 registration for an announced /24),
	// so an owned record also counts as in scope when a netblock linked to
	// it is.
	inScope := h.plugin.isEntityInScope(e.Session, e.Entity)
	if h.ownedBySeed(e) {
		if !inScope {
			for _, nb := range h.plugin.getRegisteredNetblockEntities(e.Session, e.Entity) {
				if h.plugin.isEntityInScope(e.Session, nb) {
					inScope = true
					break
				}
			}
		}
		if inScope {
			h.expand(e.Session, e.Entity, "registration record", orgs, locs)
			return
		}
	}

	match := h.firstInScope(e.Session, orgs, locs)
	if match == nil {
		if inScope {
			if rec, ok := e.Entity.Asset.(*oamreg.IPNetRecord); ok {
				e.Session.Log().Info("not expanding scope from netblock registration: registrant not attributed to the target",
					"cidr", rec.CIDR.String(), "registrant", rec.Name,
					slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
			}
		}
		return
	}
	// a block registered to another organization is not admitted because an
	// address or organization in its record matched (a shared office, a
	// parent company's address)
	if h.declineForeign(e) {
		return
	}

	// the netblocks the record registers should be added to the scope
	for _, nb := range h.plugin.getRegisteredNetblockEntities(e.Session, e.Entity) {
		h.plugin.enqueueIfOutOfScope(e.Session, nb, match, "registrant match")
	}
	h.expand(e.Session, match, "registrant match", orgs, locs)
}

// ownedBySeed reports whether the IPNetRecord is attributed to the target
// by an RDAP contact email on a seed domain.
func (h *horRegRec) ownedBySeed(e *et.Event) bool {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	owned, _ := support.IPNetRecordOwnedBySeed(ctx, e.Session, e.Entity)
	return owned
}
