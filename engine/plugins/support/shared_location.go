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

// IsSharedLocation reports whether the Location entity is used by more than
// MaxRecordsPerLocation records, and the number of records using it. Errors
// fail open (not shared), which keeps the previous behavior.
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

	// Every record ever linked to the address counts, whatever its age:
	// an address is shared because of how many parties use it, not because
	// of when they were seen.
	edges, err := sess.DB().IncomingEdges(ctx, loc, time.Time{}, "legal_address", "hq_address", "location")
	if err != nil {
		return false, 0
	}

	froms := make(map[string]struct{}, len(edges))
	for _, edge := range edges {
		if edge.FromEntity != nil {
			froms[edge.FromEntity.ID] = struct{}{}
		}
	}

	n := len(froms)
	if n > MaxRecordsPerLocation {
		sharedLocations.Store(loc.ID, n)
		return true, n
	}
	return false, n
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
