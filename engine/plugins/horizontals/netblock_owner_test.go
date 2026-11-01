// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// setScope is a session scope holding exact assets, keyed by type and key.
type setScope struct {
	et.Scope
	mu  sync.Mutex
	set map[string]struct{}
}

func scopeKey(a oam.Asset) string { return string(a.AssetType()) + "|" + a.Key() }

func (s *setScope) Add(a oam.Asset) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := scopeKey(a)
	if _, ok := s.set[k]; ok {
		return false
	}
	s.set[k] = struct{}{}
	return true
}

func (s *setScope) has(a oam.Asset) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.set[scopeKey(a)]
	return ok
}

func (s *setScope) IsAssetInScope(a oam.Asset, _ int) (oam.Asset, int) {
	if r, ok := a.(*oamreg.IPNetRecord); ok {
		a = &oamnet.Netblock{CIDR: r.CIDR, Type: r.Type}
	}
	if s.has(a) {
		return a, 100
	}
	return nil, 0
}

type nopBacklog struct{ et.Backlog }

func (nopBacklog) Enqueue(*dbt.Entity) error { return nil }

type ownerTestSession struct {
	et.Session
	id    uuid.UUID
	db    repository.Repository
	cfg   *config.Config
	scope *setScope
}

func (s *ownerTestSession) ID() uuid.UUID             { return s.id }
func (s *ownerTestSession) Ctx() context.Context      { return context.Background() }
func (s *ownerTestSession) Log() *slog.Logger         { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func (s *ownerTestSession) Config() *config.Config    { return s.cfg }
func (s *ownerTestSession) DB() repository.Repository { return s.db }
func (s *ownerTestSession) Scope() et.Scope           { return s.scope }
func (s *ownerTestSession) Backlog() et.Backlog       { return nopBacklog{} }

// The blue.cl incident: blue.cl's hosts sit on a small Salesforce block, so
// the ambient path put the block in scope. Its registration record's
// registrant (Salesforce) must not then be added to scope: that made the
// target a tenant, not the owner. A block whose RDAP contact is on a seed
// domain is the target's own, and its registrant is still expanded.
func TestInScopeNetblockRegistrantNeedsOwnership(t *testing.T) {
	for _, tc := range []struct {
		name   string
		email  string
		expand bool
	}{
		{"hosted on a provider's block", "hostmaster@salesforce.com", false},
		{"the target's own block", "noc@blue.cl", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
			if err != nil {
				t.Fatalf("failed to open the test asset database: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })

			cfg := config.NewConfig()
			cfg.AddDomains("blue.cl")
			cfg.Transformations = map[string]*config.Transformation{}
			for _, from := range []string{"ipnetrecord", "contactrecord", "organization", "location", "netblock"} {
				cfg.Transformations[from+"->all"] = &config.Transformation{From: from, To: "all", TTL: 1440, Confidence: 50}
			}

			sess := &ownerTestSession{id: uuid.New(), db: db, cfg: cfg, scope: &setScope{set: map[string]struct{}{}}}
			ctx := context.Background()
			create := func(a oam.Asset) *dbt.Entity {
				ent, err := db.CreateAsset(ctx, a)
				if err != nil || ent == nil {
					t.Fatalf("failed to create %T: %v", a, err)
				}
				return ent
			}
			edge := func(label string, from, to *dbt.Entity) {
				if _, err := db.CreateEdge(ctx, &dbt.Edge{
					Relation:   &general.SimpleRelation{Name: label},
					FromEntity: from,
					ToEntity:   to,
				}); err != nil {
					t.Fatal(err)
				}
			}

			cidr := netip.MustParsePrefix("96.43.144.0/20")
			rec := create(&oamreg.IPNetRecord{
				CIDR: cidr, Handle: "NET-96-43-144-0-1", Type: "IPv4", Name: "SALESF-3",
				StartAddress: netip.MustParseAddr("96.43.144.0"), EndAddress: netip.MustParseAddr("96.43.159.255"),
			})
			cr := create(&oamcon.ContactRecord{DiscoveredAt: "https://rdap.arin.net/registry/entity/SALESF-3"})
			loc := create(&oamcon.Location{
				Address:        "Attn: Accounts Payable 415 Mission Street, 3rd Floor San Francisco CA 94105 United States",
				BuildingNumber: "415", StreetName: "mission street", City: "san francisco", Province: "ca",
				PostalCode: "94105", Country: "US",
			})
			org := create(&oamorg.Organization{ID: uuid.NewString(), Name: "Salesforce, Inc."})
			email := create(&general.Identifier{UniqueID: "email:" + tc.email, ID: tc.email, Type: general.EmailAddress})
			edge("registrant", rec, cr)
			edge("location", cr, loc)
			edge("organization", cr, org)
			edge("id", cr, email)

			// the block is in scope through the ambient path
			sess.scope.Add(&oamnet.Netblock{CIDR: cidr, Type: "IPv4"})

			h := &horRegRec{name: "Horizontals-Registration-Record-Handler", plugin: NewHorizontals().(*horizPlugin)}
			if err := h.check(&et.Event{Name: cidr.String(), Entity: rec, Session: sess}); err != nil {
				t.Fatal(err)
			}

			if got := sess.scope.has(loc.Asset); got != tc.expand {
				t.Errorf("registrant location in scope = %v, want %v", got, tc.expand)
			}
			if got := sess.scope.has(org.Asset); got != tc.expand {
				t.Errorf("registrant organization in scope = %v, want %v", got, tc.expand)
			}
		})
	}
}
