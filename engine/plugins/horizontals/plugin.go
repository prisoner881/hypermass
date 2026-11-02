// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/net/publicsuffix"
)

type horizPlugin struct {
	name        string
	log         *slog.Logger
	horfqdn     *horfqdn
	horaddr     *horaddr
	horOrg      *horOrg
	horLocation *horLocation
	horRegRec   *horRegRec
	horTlsCert  *horTlsCert
	source      *et.Source
}

func NewHorizontals() et.Plugin {
	return &horizPlugin{
		name: "Horizontals",
		source: &et.Source{
			Name:       "Horizontals",
			Confidence: 75,
		},
	}
}

func (h *horizPlugin) Name() string {
	return h.name
}

func (h *horizPlugin) Start(r et.Registry) error {
	h.log = r.Log().WithGroup("plugin").With("name", h.name)

	h.horfqdn = &horfqdn{
		name:   h.name + "-FQDN-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horfqdn.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     h.horfqdn.check,
	}); err != nil {
		return err
	}

	h.horaddr = &horaddr{
		name:   h.name + "-IPAddress-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horaddr.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.IPAddress,
		Callback:     h.horaddr.check,
	}); err != nil {
		return err
	}

	h.horOrg = &horOrg{
		name:   h.name + "-Organization-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horOrg.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Organization)},
		EventType:    oam.Organization,
		Callback:     h.horOrg.check,
	}); err != nil {
		return err
	}

	h.horLocation = &horLocation{
		name:   h.name + "-Location-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horLocation.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Location)},
		EventType:    oam.Location,
		Callback:     h.horLocation.check,
	}); err != nil {
		return err
	}

	h.horRegRec = &horRegRec{
		name:   h.name + "-Registration-Record-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horRegRec.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.AutnumRecord)},
		EventType:    oam.AutnumRecord,
		Callback:     h.horRegRec.check,
	}); err != nil {
		return err
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horRegRec.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.DomainRecord)},
		EventType:    oam.DomainRecord,
		Callback:     h.horRegRec.check,
	}); err != nil {
		return err
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horRegRec.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.IPNetRecord)},
		EventType:    oam.IPNetRecord,
		Callback:     h.horRegRec.check,
	}); err != nil {
		return err
	}

	h.horTlsCert = &horTlsCert{
		name:   h.name + "-TLS-Certificate-Handler",
		plugin: h,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.horTlsCert.name,
		Position:     10,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.TLSCertificate)},
		EventType:    oam.TLSCertificate,
		Callback:     h.horTlsCert.check,
	}); err != nil {
		return err
	}

	h.log.Info("Plugin started")
	return nil
}

func (h *horizPlugin) Stop() {
	h.log.Info("Plugin stopped")
}

func (h *horizPlugin) submitIPAddress(e *et.Event, asset *oamnet.IPAddress, src *et.Source) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	// ensure we do not work on an IP address that was processed previously
	_, err := e.Session.DB().FindEntitiesByContent(ctx, oam.IPAddress, e.Session.StartTime(), 1, dbt.ContentFilters{
		"address": asset.Address.String(),
	})
	if err == nil {
		return
	}

	addr, err := e.Session.DB().CreateAsset(ctx, asset)
	if err == nil && addr != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, addr, &oamgen.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    addr.Asset.Key(),
			Entity:  addr,
			Session: e.Session,
		})
	}
}

func (h *horizPlugin) getContactRecord(sess et.Session, ent *dbt.Entity, label string) (*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(),
		string(ent.Asset.AssetType()), string(oam.ContactRecord), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, ent, since, label)
	if err != nil || len(edges) == 0 {
		return nil, errors.New("failed to obtain the contact record")
	}

	to, err := sess.DB().FindEntityById(ctx, edges[0].ToEntity.ID)
	if err != nil {
		return nil, err
	}

	if _, valid := to.Asset.(*oamcon.ContactRecord); valid {
		return to, nil
	}
	return nil, errors.New("failed to cast the ContactRecord entity")
}

// lookupContactRecordOrgsAndLocations returns the organizations and locations
// of the contact record. Shared addresses (support.SkipSharedLocation) are
// left out: they are not evidence of ownership, so they must neither enter
// scope nor make a record look related to one that is in scope.
func (h *horizPlugin) lookupContactRecordOrgsAndLocations(sess et.Session, cr *dbt.Entity) ([]*dbt.Entity, []*dbt.Entity) {
	var orgents []*dbt.Entity

	if ents, err := h.getContactRecordOrganizations(sess, cr); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if _, valid := ent.Asset.(*oamorg.Organization); valid {
				orgents = append(orgents, ent)
			}
		}
	}

	set := stringset.New()
	defer set.Close()

	var locents []*dbt.Entity
	for _, o := range orgents {
		if ents, err := h.getOrganizationLocations(sess, o); err == nil && len(ents) > 0 {
			for _, ent := range ents {
				if set.Has(ent.ID) {
					continue
				}
				if _, valid := ent.Asset.(*oamcon.Location); valid {
					set.Insert(ent.ID)
					if !support.SkipSharedLocation(sess, ent, h.name) {
						locents = append(locents, ent)
					}
				}
			}
		}
	}

	if ents, err := h.getContactRecordLocations(sess, cr); err == nil && len(ents) > 0 {
		for _, ent := range ents {
			if set.Has(ent.ID) {
				continue
			}
			if _, valid := ent.Asset.(*oamcon.Location); valid {
				set.Insert(ent.ID)
				if !support.SkipSharedLocation(sess, ent, h.name) {
					locents = append(locents, ent)
				}
			}
		}
	}

	return orgents, locents
}

func (h *horizPlugin) getContactRecordOrganizations(sess et.Session, cr *dbt.Entity) ([]*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(),
		string(oam.ContactRecord), string(oam.Organization), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, cr, since, "organization")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("zero organizations found")
	}

	seconds := 5 * len(edges)
	octx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
	defer cancel()

	var results []*dbt.Entity
	for _, edge := range edges {
		to, err := sess.DB().FindEntityById(octx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		// an organization named after a role ("Domain Administrator")
		// links unrelated registrants; it is not evidence of ownership
		if _, valid := to.Asset.(*oamorg.Organization); valid && !support.SkipRoleOrganization(sess, to, h.name) {
			results = append(results, to)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("failed to extract the organization")
	}
	return results, nil
}

func (h *horizPlugin) getContactRecordLocations(sess et.Session, cr *dbt.Entity) ([]*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(),
		string(oam.ContactRecord), string(oam.Location), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, cr, since, "location")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("zero locations found")
	}

	seconds := 5 * len(edges)
	lctx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
	defer cancel()

	var results []*dbt.Entity
	for _, edge := range edges {
		to, err := sess.DB().FindEntityById(lctx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		if _, valid := to.Asset.(*oamcon.Location); valid {
			results = append(results, to)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("failed to extract the locations")
	}
	return results, nil
}

func (h *horizPlugin) getOrganizationLocations(sess et.Session, o *dbt.Entity) ([]*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(),
		string(oam.Organization), string(oam.Location), h.name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 5*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, o, since, "hq_address", "location")
	if err != nil || len(edges) == 0 {
		return nil, errors.New("zero locations found")
	}

	seconds := 5 * len(edges)
	lctx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
	defer cancel()

	var results []*dbt.Entity
	for _, edge := range edges {
		to, err := sess.DB().FindEntityById(lctx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		if _, valid := to.Asset.(*oamcon.Location); valid {
			results = append(results, to)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("failed to extract the locations")
	}
	return results, nil
}

// maxAnnouncedNetblocksForScope is a backstop for the ASN netblock fan-out
// in addASNetblocksToScope: an autonomous system announcing more netblocks
// than this is treated as shared infrastructure (a cloud or CDN provider)
// and does not enter scope at all. Which ASNs reach the fan-out is decided
// by their registration (horizontals only follows an ASN whose registrant
// is in scope, and declines one whose registration names another
// organization), so this only has to catch the very largest providers. The
// previous limit of 16 also caught companies that run their own networks
// (American Express, Bank of America, General Motors and Eli Lilly each
// announce 80-120), so their own ASN never brought its blocks into scope.
// Tunable.
const maxAnnouncedNetblocksForScope = 500

// isSharedInfrastructureASN reports whether an autonomous system that
// announces announcedNetblocks blocks should be treated as shared
// infrastructure, whose announced space must not be admitted to scope.
func isSharedInfrastructureASN(announcedNetblocks int) bool {
	return announcedNetblocks > maxAnnouncedNetblocksForScope
}

// addASNetblocksToScope admits the small netblocks the autonomous system
// announces and returns its entity for the caller to add to scope, or nil
// when the AS is shared infrastructure, which must not enter scope at all.
func (h *horizPlugin) addASNetblocksToScope(sess et.Session, asn int) *dbt.Entity {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	var as *dbt.Entity
	if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.AutonomousSystem, time.Time{}, 1, dbt.ContentFilters{
		"number": asn,
	}); err == nil && len(ents) == 1 {
		as = ents[0]
	}
	if as == nil {
		return nil
	}

	since, err := support.TTLStartTime(sess.Config(), string(oam.AutonomousSystem), string(oam.Netblock), h.name)
	if err != nil {
		return as
	}

	if edges, err := sess.DB().OutgoingEdges(ctx, as, since, "announces"); err == nil && len(edges) > 0 {
		// Shared-infrastructure guard. This path is reached whenever a seed
		// domain merely resolves onto a provider (e.g. a Cloudflare-fronted
		// site), so admitting every block the ASN announces would put the
		// provider's entire address space in scope and port-scan it. The
		// per-netblock ambient gate in ip_netblock.go does not cover this ASN
		// fan-out, so bound it here. Blocks the target genuinely owns still
		// reach scope at any size via the ownership path
		// (support.AdmitOwnedNetblock, gated on RDAP contact attribution).
		// A shared ASN does not enter scope, not even the AS itself: an AS
		// in scope makes its registration record's registrant count as the
		// target's. In observe and off modes the previous behavior holds:
		// the AS is returned, but its announced blocks are not admitted.
		if isSharedInfrastructureASN(len(edges)) {
			if support.Decline(sess, support.VetoSharedASN, string(oam.AutonomousSystem), "AS"+strconv.Itoa(asn), h.name,
				"announced_netblocks", len(edges), "max_announced_netblocks", maxAnnouncedNetblocksForScope) {
				return nil
			}
			return as
		}

		seconds := 5 * len(edges)

		ctx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
		defer cancel()

		for _, edge := range edges {
			to, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID)
			if err != nil || to == nil {
				continue
			}
			// Admit only small IPv4 blocks on this associative signal, as the
			// ambient netblock path does; larger or genuinely-owned blocks
			// come through the ownership path instead.
			if nb, ok := to.Asset.(*oamnet.Netblock); ok && support.PrefixEligibleForAmbientAdmit(nb.CIDR) {
				h.enqueueIfOutOfScope(sess, to, as, "announced by an in-scope ASN")
			}
		}
	}

	return as
}

func (h *horizPlugin) confidence(sess et.Session, atype oam.AssetType) int {
	tstr := string(atype)

	if matches, err := sess.Config().CheckTransformations(tstr, tstr); err == nil && matches != nil {
		if conf := matches.Confidence(h.name); conf > 0 {
			return conf
		}
		if conf := matches.Confidence(tstr); conf > 0 {
			return conf
		}
	}

	return -1
}

func (h *horizPlugin) isEntityInScope(sess et.Session, ent *dbt.Entity) bool {
	econf := h.confidence(sess, ent.Asset.AssetType())
	if econf <= 0 {
		return false
	}

	if _, conf := sess.Scope().IsAssetInScope(ent.Asset, econf); conf >= econf {
		return true
	}
	return false
}

// addToScopeAndEnqueue adds the asset to scope because of the in-scope
// asset from (nil when unknown), via the named kind of evidence, and logs
// it with its distance from the seeds (-1 when unknown).
func (h *horizPlugin) addToScopeAndEnqueue(sess et.Session, ent, from *dbt.Entity, via string) {
	if sess.Scope().Add(ent.Asset) {
		// The TLS certificate and registration record handlers add assets
		// here without an association rationale, so record each one.
		var fromAsset oam.Asset
		fromName := ""
		if from != nil {
			fromAsset = from.Asset
			fromName = string(from.Asset.AssetType()) + ": " + from.Asset.Key()
		}
		distance := support.RecordScopeAddition(sess, ent.Asset, fromAsset)
		sess.Log().Info("asset added to the session scope by horizontals",
			"type", string(ent.Asset.AssetType()), "asset", ent.Asset.Key(),
			"via", via, "from", fromName, "distance", distance,
			slog.Group("plugin", "name", h.name))
		if econf := h.confidence(sess, ent.Asset.AssetType()); econf > 0 {
			if a, conf := sess.Scope().IsAssetInScope(ent.Asset, econf); conf >= econf {
				if strings.EqualFold(a.Key(), ent.Asset.Key()) {
					_ = sess.Backlog().Enqueue(ent)
				}
			}
		}
	}
}

func (h *horizPlugin) enqueueIfOutOfScope(sess et.Session, ent, from *dbt.Entity, via string) {
	if !h.isEntityInScope(sess, ent) {
		h.addToScopeAndEnqueue(sess, ent, from, via)
	}
}

// associationDistance records an addition made by scope association and
// returns its distance from the seeds.
func associationDistance(sess et.Session, assoc *et.Association) int {
	if assoc == nil || assoc.Submission == nil {
		return -1
	}
	var from oam.Asset
	if assoc.BestMatch != nil {
		from = assoc.BestMatch.Asset
	}
	return support.RecordScopeAddition(sess, assoc.Submission.Asset, from)
}

// expandFromContactRecord adds to scope what a contact record using the
// in-scope location or organization from leads to: the record's other
// organizations and locations, and the domain, netblock, autonomous system
// or certificate domain it is a contact for. Registrations naming another
// organization, and merged certificates, are declined.
func (h *horizPlugin) expandFromContactRecord(sess et.Session, cr, from *dbt.Entity, via string, since time.Time) {
	// add the contact record orgs and locations to the scope
	if orgs, locs := h.lookupContactRecordOrgsAndLocations(sess, cr); len(orgs) > 0 || len(locs) > 0 {
		for _, o := range orgs {
			h.enqueueIfOutOfScope(sess, o, from, via)
		}
		for _, loc := range locs {
			h.enqueueIfOutOfScope(sess, loc, from, via)
		}
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), time.Minute)
	defer cancel()

	// if the contact record belongs to a registration record or TLS certificate, add to the scope
	edges, err := sess.DB().IncomingEdges(ctx, cr, since)
	if err != nil {
		return
	}
	for _, edge := range edges {
		rec, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil {
			continue
		}
		switch v := rec.Asset.(type) {
		case *oamreg.AutnumRecord:
			if !h.isEntityInScope(sess, rec) &&
				!support.IsSeedAsset(sess, &oamnet.AutonomousSystem{Number: v.Number}) &&
				support.DeclineForeignRegistration(sess, rec, h.name) {
				continue
			}
			if !h.isEntityInScope(sess, rec) {
				if as := h.addASNetblocksToScope(sess, v.Number); as != nil {
					h.addToScopeAndEnqueue(sess, as, from, via)
				}
			}
		case *oamreg.DomainRecord:
			if fqdn, err := h.getRegisteredDomainEntity(sess, rec); err == nil && fqdn != nil {
				h.enqueueIfOutOfScope(sess, fqdn, from, via)
			}
		case *oamreg.IPNetRecord:
			var nbs []*dbt.Entity
			var seed bool
			for _, nb := range h.getRegisteredNetblockEntities(sess, rec) {
				if h.isEntityInScope(sess, nb) {
					continue
				}
				if support.IsSeedAsset(sess, nb.Asset) {
					seed = true
				}
				nbs = append(nbs, nb)
			}
			if len(nbs) == 0 || (!seed && support.DeclineForeignRegistration(sess, rec, h.name)) {
				continue
			}
			for _, nb := range nbs {
				h.enqueueIfOutOfScope(sess, nb, from, via)
			}
		case *oamcert.TLSCertificate:
			if !support.DeclineMergedCertificate(sess, rec, h.name) {
				h.enqueueCertificateDomain(sess, rec, from, via)
			}
		}
	}
}

// enqueueCertificateDomain adds the registered domain of the certificate's
// common name to scope and queues that domain's FQDN for processing. A
// certificate names a host (www.example.com), and only a registered domain
// can be added to scope, so adding the certificate itself did nothing for
// most certificates. Falls back to the certificate when the domain's FQDN
// is not in the database.
func (h *horizPlugin) enqueueCertificateDomain(sess et.Session, cert, from *dbt.Entity, via string) {
	c, ok := cert.Asset.(*oamcert.TLSCertificate)
	if !ok {
		return
	}

	name := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(c.SubjectCommonName)), "*.")
	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
		defer cancel()

		if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{
			"name": dom,
		}); err == nil && len(ents) == 1 {
			h.enqueueIfOutOfScope(sess, ents[0], from, via)
			return
		}
	}

	h.enqueueIfOutOfScope(sess, cert, from, via)
}

func (h *horizPlugin) getRegisteredDomainEntity(sess et.Session, record *dbt.Entity) (*dbt.Entity, error) {
	dr, valid := record.Asset.(*oamreg.DomainRecord)
	if !valid {
		return nil, errors.New("failed to cast the DomainRecord")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{
		"name": dr.Domain,
	}); err == nil && len(ents) == 1 {
		return ents[0], nil
	}

	return nil, fmt.Errorf("failed to obtain the registered domain name FQDN for: %s", dr.Domain)
}

// maxRegisteredNetblocks bounds how many netblocks linked to one
// registration record are considered. A record is stored under the range it
// registers and linked from each netblock it covers; a provider's large
// registration can be linked from many.
const maxRegisteredNetblocks = 64

// getRegisteredNetblockEntities returns the netblocks the IPNetRecord
// registers: those linked to it by a "registration" edge (the netblocks
// RDAP was queried for, which may be smaller than the registered range),
// and the netblock with the record's own CIDR when one is stored.
func (h *horizPlugin) getRegisteredNetblockEntities(sess et.Session, record *dbt.Entity) []*dbt.Entity {
	iprec, valid := record.Asset.(*oamreg.IPNetRecord)
	if !valid {
		return nil
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	var results []*dbt.Entity
	seen := make(map[string]struct{})
	add := func(ent *dbt.Entity) {
		if ent == nil {
			return
		}
		if _, ok := ent.Asset.(*oamnet.Netblock); !ok {
			return
		}
		if _, dup := seen[ent.ID]; !dup {
			seen[ent.ID] = struct{}{}
			results = append(results, ent)
		}
	}

	if edges, err := sess.DB().IncomingEdges(ctx, record, time.Time{}, "registration"); err == nil {
		for _, edge := range edges {
			if len(results) >= maxRegisteredNetblocks {
				break
			}
			if edge.FromEntity == nil {
				continue
			}
			if ent, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil {
				add(ent)
			}
		}
	}
	if len(results) < maxRegisteredNetblocks {
		if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Netblock, time.Time{}, 1, dbt.ContentFilters{
			"cidr": iprec.CIDR.String(),
		}); err == nil && len(ents) == 1 {
			add(ents[0])
		}
	}
	return results
}
