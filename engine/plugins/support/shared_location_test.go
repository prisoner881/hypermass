// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
)

type sharedLocTestSession struct {
	et.Session
	id uuid.UUID
	db repository.Repository
}

func (s *sharedLocTestSession) ID() uuid.UUID        { return s.id }
func (s *sharedLocTestSession) Ctx() context.Context { return context.Background() }
func (s *sharedLocTestSession) Log() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
func (s *sharedLocTestSession) DB() repository.Repository { return s.db }

// linkContactRecords creates n contact records that use the location.
func linkContactRecords(t *testing.T, db repository.Repository, loc *dbt.Entity, prefix string, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		cr, err := db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: fmt.Sprintf("%s-%d", prefix, i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.CreateEdge(ctx, &dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "location"},
			FromEntity: cr,
			ToEntity:   loc,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// A privacy proxy's address, used by thousands of contact records, must not
// carry scope; an organization's own address, used by a few, still does.
func TestIsSharedLocation(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sess := &sharedLocTestSession{id: uuid.New(), db: db}
	ctx := context.Background()

	proxy, err := db.CreateAsset(ctx, &oamcon.Location{
		Address:        "c/o whoisproxy.com 604 Cameron Street Alexandria VA 22314 US",
		BuildingNumber: "604", StreetName: "cameron street", City: "alexandria",
		Province: "VA", PostalCode: "22314", Country: "US",
	})
	if err != nil {
		t.Fatal(err)
	}
	office, err := db.CreateAsset(ctx, &oamcon.Location{
		Address:        "Gullhaug Torg 5 Oslo 0484 NO",
		BuildingNumber: "5", StreetName: "gullhaug torg", City: "oslo",
		PostalCode: "0484", Country: "NO",
	})
	if err != nil {
		t.Fatal(err)
	}

	// exactly at the cap: still an ordinary address
	linkContactRecords(t, db, proxy, "proxy", MaxRecordsPerLocation)
	if shared, n := IsSharedLocation(sess, proxy); shared || n != MaxRecordsPerLocation {
		t.Fatalf("at the cap: got shared=%v n=%d, want false %d", shared, n, MaxRecordsPerLocation)
	}
	if SkipSharedLocation(sess, proxy, "test") {
		t.Fatal("at the cap: want not skipped")
	}

	// one over the cap: shared, and stays shared
	linkContactRecords(t, db, proxy, "proxy-more", 1)
	if shared, n := IsSharedLocation(sess, proxy); !shared || n != MaxRecordsPerLocation+1 {
		t.Fatalf("over the cap: got shared=%v n=%d, want true %d", shared, n, MaxRecordsPerLocation+1)
	}
	if !SkipSharedLocation(sess, proxy, "test") || !SkipSharedLocation(sess, proxy, "test") {
		t.Fatal("over the cap: want skipped on every check")
	}

	linkContactRecords(t, db, office, "office", 3)
	if shared, n := IsSharedLocation(sess, office); shared || n != 3 {
		t.Fatalf("office: got shared=%v n=%d, want false 3", shared, n)
	}

	// anything other than a Location is never shared
	cr, err := db.CreateAsset(ctx, &oamcon.ContactRecord{DiscoveredAt: "not-a-location"})
	if err != nil {
		t.Fatal(err)
	}
	if shared, _ := IsSharedLocation(sess, cr); shared {
		t.Fatal("contact record: want not shared")
	}
	if shared, _ := IsSharedLocation(sess, nil); shared {
		t.Fatal("nil: want not shared")
	}
}

// The blue.cl incident: "Salesforce, Inc. 415 Mission Street ..." was
// skipped as shared, but "Attn: Accounts Payable 415 Mission Street ..." (the
// same building, stored as a separate Location with a handful of records)
// was admitted. Records count across every variant of the building.
func TestIsSharedLocationCountsAddressVariants(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sess := &sharedLocTestSession{id: uuid.New(), db: db}
	ctx := context.Background()

	mission := func(address, country string) *dbt.Entity {
		ent, err := db.CreateAsset(ctx, &oamcon.Location{
			Address: address, BuildingNumber: "415", StreetName: "mission street",
			City: "san francisco", Province: "ca", PostalCode: "94105", Country: country,
		})
		if err != nil {
			t.Fatal(err)
		}
		return ent
	}
	main := mission("Salesforce, Inc. 415 Mission Street, 3rd Floor San Francisco CA 94105 US", "US")
	ap := mission("Attn: Accounts Payable 415 Mission Street, 3rd Floor San Francisco CA 94105 United States", "US")
	legal := mission("Legal Department 415 Mission Street San Francisco CA 94105 US", "US")
	next, err := db.CreateAsset(ctx, &oamcon.Location{
		Address: "Some Startup 417 Mission Street San Francisco CA 94105 US", BuildingNumber: "417",
		StreetName: "mission street", City: "san francisco", Province: "ca", Country: "US",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 12 + 10 + 4 = 26 records at 415 Mission, none over the cap alone
	linkContactRecords(t, db, main, "main", 12)
	linkContactRecords(t, db, ap, "ap", 10)
	linkContactRecords(t, db, legal, "legal", 4)
	linkContactRecords(t, db, next, "next", 3)

	if shared, n := IsSharedLocation(sess, ap); !shared || n != 26 {
		t.Fatalf("Accounts Payable variant: got shared=%v n=%d, want true 26", shared, n)
	}
	// the verdict covers the other variants without counting again
	for _, v := range []*dbt.Entity{main, legal} {
		if shared, _ := IsSharedLocation(sess, v); !shared {
			t.Fatalf("%s: want shared", v.Asset.Key())
		}
	}
	// a neighbouring building is a different address
	if shared, n := IsSharedLocation(sess, next); shared || n != 3 {
		t.Fatalf("417 Mission: got shared=%v n=%d, want false 3", shared, n)
	}
}
