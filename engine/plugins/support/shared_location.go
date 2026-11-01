// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"log/slog"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
)

// MaxRecordsPerLocation bounds how many records (WHOIS/RDAP contact records,
// organizations) may use one street address before the address is treated
// as shared: a WHOIS privacy/proxy service, a registered agent or a hosting
// company. A shared address says nothing about who owns a domain, so it must
// not carry scope from one record to another. Without this bound, an
// in-scope domain registered through a privacy proxy puts the proxy's
// address in scope, and every other domain behind that proxy follows (the
// c/o whoisproxy.com address in Alexandria, VA is used by 19,000+ contact
// records). A real organization's address is used by a handful of records,
// so this cleanly separates the two. Tunable.
const MaxRecordsPerLocation = 25

var (
	// location entity ID -> record count, for locations found to be shared.
	// A shared verdict never needs re-checking: records are only ever added
	// to the database, so the count can only grow. Locations under the cap
	// are not cached and are counted again on the next check, since they
	// may still cross it.
	sharedLocations sync.Map
	// session ID + location entity ID, so each session logs a skipped
	// location once rather than at every record that uses it.
	sharedLocationsLogged sync.Map
)

// maxSameAddressLocations bounds how many stored variants of one address
// (other Location entities at the same building) are counted.
const maxSameAddressLocations = 500

// IsSharedLocation reports whether the Location entity is an address used
// by more than MaxRecordsPerLocation records, and the number of records
// counted. Records are counted across every stored variant of the same
// address, not just this entity: the same building is often stored under
// several free-text forms ("Salesforce, Inc. 415 Mission Street, 3rd Floor
// ..." and "Attn: Accounts Payable 415 Mission Street, 3rd Floor ..."), each
// with only a few records, while scope matching treats them all as one
// address. Variants are the Locations with the same building number,
// street, city and province (the fields scope matching compares); an
// address without a building number, street or city is counted on its own.
// Errors fail open (not shared), which keeps the previous behavior.
func IsSharedLocation(sess et.Session, loc *dbt.Entity) (bool, int) {
	if loc == nil {
		return false, 0
	}
	if _, ok := loc.Asset.(*oamcon.Location); !ok {
		return false, 0
	}
	if v, ok := sharedLocations.Load(loc.ID); ok {
		return true, v.(int)
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	variants := append([]*dbt.Entity{loc}, sameAddressLocations(ctx, sess, loc)...)

	// Every record ever linked to the address counts, whatever its age:
	// an address is shared because of how many parties use it, not because
	// of when they were seen.
	froms := make(map[string]struct{})
	for i, v := range variants {
		edges, err := sess.DB().IncomingEdges(ctx, v, time.Time{}, "legal_address", "hq_address", "location")
		if err != nil {
			if i == 0 {
				return false, 0
			}
			continue
		}
		for _, edge := range edges {
			if edge.FromEntity != nil {
				froms[edge.FromEntity.ID] = struct{}{}
			}
		}
		if len(froms) > MaxRecordsPerLocation {
			break
		}
	}

	n := len(froms)
	if n > MaxRecordsPerLocation {
		// the verdict holds for every variant of the address
		for _, v := range variants {
			sharedLocations.Store(v.ID, n)
		}
		return true, n
	}
	return false, n
}

// sameAddressLocations returns the other Location entities stored for the
// same building as loc, or none when loc lacks a building number, street
// or city.
func sameAddressLocations(ctx context.Context, sess et.Session, loc *dbt.Entity) []*dbt.Entity {
	l, ok := loc.Asset.(*oamcon.Location)
	if !ok || l.BuildingNumber == "" || l.StreetName == "" || l.City == "" {
		return nil
	}

	filters := dbt.ContentFilters{
		"building_number": l.BuildingNumber,
		"street_name":     l.StreetName,
		"city":            l.City,
	}
	if l.Province != "" {
		filters["province"] = l.Province
	}

	ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Location, time.Time{}, maxSameAddressLocations, filters)
	if err != nil {
		return nil
	}

	var results []*dbt.Entity
	for _, ent := range ents {
		if ent.ID != loc.ID {
			results = append(results, ent)
		}
	}
	return results
}

// SkipSharedLocation reports whether the Location entity is a shared address
// that must not be used to expand or match scope, logging the first skip of
// each location in each session.
func SkipSharedLocation(sess et.Session, loc *dbt.Entity, plugin string) bool {
	shared, n := IsSharedLocation(sess, loc)
	if !shared {
		return false
	}

	key := sess.ID().String() + "|" + loc.ID
	if _, logged := sharedLocationsLogged.LoadOrStore(key, struct{}{}); !logged {
		sess.Log().Info("skipping location: shared address (likely a privacy proxy, registered agent or host)",
			"address", loc.Asset.Key(), "records", n, "max_records", MaxRecordsPerLocation,
			slog.Group("plugin", "name", plugin))
	}
	return true
}
