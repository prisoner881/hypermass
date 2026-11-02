// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// A netblock whose registration names another organization is not admitted
// because an address in its record matched one in scope (a shared office, a
// parent company's address). In observe mode it is admitted as before.
func TestForeignRegistrationNotAdmitted(t *testing.T) {
	for _, c := range []struct {
		mode  string
		admit bool
	}{
		{"enforce", false},
		{"observe", true},
		{"off", true},
	} {
		t.Run(c.mode, func(t *testing.T) {
			db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
			if err != nil {
				t.Fatalf("failed to open the test asset database: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })

			id := uuid.New()
			cfg := config.NewConfig()
			cfg.AddDomains("blue.cl")
			cfg.ScopeVetoes = c.mode
			cfg.GraphDBs = []*config.Database{{System: "sqlite", Primary: true, DBName: id.String()}}
			cfg.Transformations = map[string]*config.Transformation{}
			for _, from := range []string{"ipnetrecord", "contactrecord", "organization", "location", "netblock"} {
				cfg.Transformations[from+"->all"] = &config.Transformation{From: from, To: "all", TTL: 1440, Confidence: 50}
			}
			sess := &ownerTestSession{id: id, db: db, cfg: cfg, scope: &setScope{set: map[string]struct{}{}}}

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
					Relation: &general.SimpleRelation{Name: label}, FromEntity: from, ToEntity: to,
				}); err != nil {
					t.Fatal(err)
				}
			}

			cidr := netip.MustParsePrefix("96.43.144.0/20")
			nb := create(&oamnet.Netblock{CIDR: cidr, Type: "IPv4"})
			rec := create(&oamreg.IPNetRecord{
				CIDR: cidr, Handle: "NET-96-43-144-0-1", Type: "IPv4", Name: "SALESF-3",
				StartAddress: netip.MustParseAddr("96.43.144.0"), EndAddress: netip.MustParseAddr("96.43.159.255"),
			})
			edge("registration", nb, rec)
			cr := create(&oamcon.ContactRecord{DiscoveredAt: "https://rdap.arin.net/registry/entity/SALESF-3"})
			edge("registrant", rec, cr)
			loc := create(&oamcon.Location{
				Address:        "415 Mission Street San Francisco CA 94105 US",
				BuildingNumber: "415", StreetName: "mission street", City: "san francisco", Province: "ca", Country: "US",
			})
			edge("location", cr, loc)
			org := create(&oamorg.Organization{ID: uuid.NewString(), Name: "Salesforce, Inc."})
			edge("organization", cr, org)
			edge("id", cr, create(&general.Identifier{UniqueID: "email:abuse@salesforce.com", ID: "abuse@salesforce.com", Type: general.EmailAddress}))

			// the address is in scope (say, a tenant of the same building)
			sess.scope.Add(loc.Asset)

			h := &horRegRec{name: "Horizontals-Registration-Record-Handler", plugin: NewHorizontals().(*horizPlugin)}
			if err := h.check(&et.Event{Name: cidr.String(), Entity: rec, Session: sess}); err != nil {
				t.Fatal(err)
			}

			if got := sess.scope.has(nb.Asset); got != c.admit {
				t.Errorf("netblock in scope = %v, want %v", got, c.admit)
			}
			if got := sess.scope.has(org.Asset); got != c.admit {
				t.Errorf("registrant organization in scope = %v, want %v", got, c.admit)
			}
		})
	}
}
