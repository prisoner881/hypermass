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

type rangeFixture struct {
	sess *ownerTestSession
	nb   *dbt.Entity // the announced /24
	rec  *dbt.Entity // its /22 registration
	org  *dbt.Entity // the registrant organization
}

// newRangeFixture stores an announced /24 linked to the /22 registration
// that covers it, registered to an organization with a contact email.
func newRangeFixture(t *testing.T, email string) *rangeFixture {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	id := uuid.New()
	cfg := config.NewConfig()
	cfg.AddDomains("target.com")
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

	nb := create(&oamnet.Netblock{CIDR: netip.MustParsePrefix("198.51.101.0/24"), Type: "IPv4"})
	rec := create(&oamreg.IPNetRecord{
		CIDR: netip.MustParsePrefix("198.51.100.0/22"), Handle: "NET-198-51-100-0-1", Type: "IPv4", Name: "TARGET-AP",
		StartAddress: netip.MustParseAddr("198.51.100.0"), EndAddress: netip.MustParseAddr("198.51.103.255"),
	})
	edge("registration", nb, rec)
	cr := create(&oamcon.ContactRecord{DiscoveredAt: "https://rdap.test/entity/TARGET-AP"})
	edge("registrant", rec, cr)
	org := create(&oamorg.Organization{ID: uuid.NewString(), Name: "Target International"})
	edge("organization", cr, org)
	edge("id", cr, create(&general.Identifier{UniqueID: "email:" + email, ID: email, Type: general.EmailAddress}))

	return &rangeFixture{sess: sess, nb: nb, rec: rec, org: org}
}

func (f *rangeFixture) check(t *testing.T) {
	t.Helper()
	h := &horRegRec{name: "Horizontals-Registration-Record-Handler", plugin: NewHorizontals().(*horizPlugin)}
	if err := h.check(&et.Event{Name: "IPNetRecord", Entity: f.rec, Session: f.sess}); err != nil {
		t.Fatal(err)
	}
}

// A registration larger than the announced block: when its registrant is in
// scope, the announced /24 linked to it is admitted.
func TestRegistrantMatchAdmitsLinkedNetblock(t *testing.T) {
	f := newRangeFixture(t, "noc@target-international.example")
	f.sess.scope.Add(f.org.Asset)

	f.check(t)

	if !f.sess.scope.has(f.nb.Asset) {
		t.Error("the announced netblock under the registrant's /22 was not admitted")
	}
}

// An owned registration (contact email on a seed domain) larger than the
// announced block: when the /24 is in scope, the registrant is expanded,
// as it is for a record whose CIDR is the block itself.
func TestOwnedRegistrationExpandsFromLinkedNetblock(t *testing.T) {
	f := newRangeFixture(t, "noc@target.com")
	f.sess.scope.Add(f.nb.Asset)

	f.check(t)

	if !f.sess.scope.has(f.org.Asset) {
		t.Error("the registrant of an owned registration covering an in-scope netblock was not expanded")
	}
}

// Without a seed-domain contact or an in-scope registrant, a netblock in
// scope does not expand its registration's registrant.
func TestUnownedRegistrationNotExpandedFromLinkedNetblock(t *testing.T) {
	f := newRangeFixture(t, "noc@target-international.example")
	f.sess.scope.Add(f.nb.Asset)

	f.check(t)

	if f.sess.scope.has(f.org.Asset) {
		t.Error("the registrant was expanded without ownership")
	}
}
