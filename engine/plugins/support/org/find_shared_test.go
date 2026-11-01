// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

type findTestSession struct {
	et.Session
	id uuid.UUID
	db repository.Repository
}

func (s *findTestSession) ID() uuid.UUID             { return s.id }
func (s *findTestSession) Ctx() context.Context      { return context.Background() }
func (s *findTestSession) Log() *slog.Logger         { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func (s *findTestSession) DB() repository.Repository { return s.db }

// The crayon.co incident: a new contact record at the whoisproxy.com address
// was merged with "On behalf of kitche.co owner", another domain's record at
// the same address, pulling kitche.co into scope. An address shared by more
// than support.MaxRecordsPerLocation records must not merge organizations;
// a genuinely shared office address still does.
func TestExistsAndSharesLocEntitySharedAddress(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sess := &findTestSession{id: uuid.New(), db: db}
	ctx := context.Background()

	edge := func(label string, from, to *dbt.Entity) {
		if _, err := db.CreateEdge(ctx, &dbt.Edge{
			Relation:   &general.SimpleRelation{Name: label},
			FromEntity: from,
			ToEntity:   to,
		}); err != nil {
			t.Fatal(err)
		}
	}
	create := func(a any) *dbt.Entity {
		var ent *dbt.Entity
		var err error
		switch v := a.(type) {
		case *oamcon.Location:
			ent, err = db.CreateAsset(ctx, v)
		case *oamcon.ContactRecord:
			ent, err = db.CreateAsset(ctx, v)
		case *oamorg.Organization:
			ent, err = db.CreateAsset(ctx, v)
		}
		if err != nil || ent == nil {
			t.Fatalf("failed to create %T: %v", a, err)
		}
		return ent
	}

	// setup builds an address used by n contact records, one of which
	// belongs to the existing organization, plus the new contact record.
	setup := func(tag string, loc *oamcon.Location, n int, orgName string) (*dbt.Entity, *dbt.Entity) {
		l := create(loc)
		existing := create(&oamorg.Organization{ID: uuid.NewString(), Name: orgName})
		for i := 0; i < n; i++ {
			cr := create(&oamcon.ContactRecord{DiscoveredAt: fmt.Sprintf("%s-%d", tag, i)})
			edge("location", cr, l)
			if i == 0 {
				edge("organization", cr, existing)
			}
		}
		newcr := create(&oamcon.ContactRecord{DiscoveredAt: tag + "-new"})
		edge("location", newcr, l)
		return newcr, existing
	}

	proxyCR, _ := setup("proxy", &oamcon.Location{
		Address:        "c/o whoisproxy.com 604 Cameron Street Alexandria VA 22314 US",
		BuildingNumber: "604", StreetName: "cameron street", City: "alexandria",
		Province: "VA", PostalCode: "22314", Country: "US",
	}, support.MaxRecordsPerLocation+5, "On behalf of kitche.co owner")
	if got, err := existsAndSharesLocEntity(sess, proxyCR,
		&oamorg.Organization{Name: "On behalf of kitche.co owner"}); err == nil {
		t.Fatalf("shared proxy address: want no merge, merged with %s", got.Asset.Key())
	}

	officeCR, office := setup("office", &oamcon.Location{
		Address:        "Gullhaug Torg 5 Oslo 0484 NO",
		BuildingNumber: "5", StreetName: "gullhaug torg", City: "oslo",
		PostalCode: "0484", Country: "NO",
	}, 3, "Crayon AS")
	got, err := existsAndSharesLocEntity(sess, officeCR, &oamorg.Organization{Name: "Crayon AS"})
	if err != nil || got == nil || got.ID != office.ID {
		t.Fatalf("office address: want merge with Crayon AS, got %v, %v", got, err)
	}
}
