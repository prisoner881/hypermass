// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

func TestRegisteredPrefix(t *testing.T) {
	for _, c := range []struct {
		block, start, end string
		want              string // "" when the answer cannot be stored
		wantStart         string
		wantEnd           string
	}{
		// the registration is the announced prefix
		{"63.251.77.0/24", "63.251.77.0", "63.251.77.255", "63.251.77.0/24", "63.251.77.0", "63.251.77.255"},
		// a /21 registration announced as /24s
		{"198.184.4.0/24", "198.184.0.0", "198.184.7.255", "198.184.0.0/21", "198.184.0.0", "198.184.7.255"},
		{"203.17.34.0/24", "203.17.32.0", "203.17.35.255", "203.17.32.0/22", "203.17.32.0", "203.17.35.255"},
		// a range that is not one CIDR block: its block containing the netblock
		{"198.51.104.0/24", "198.51.96.0", "198.51.105.255", "198.51.104.0/23", "198.51.104.0", "198.51.105.255"},
		{"198.51.97.0/24", "198.51.96.0", "198.51.105.255", "198.51.96.0/21", "198.51.96.0", "198.51.103.255"},
		// an answer inside the netblock is stored under the netblock
		{"10.0.0.0/16", "10.0.5.0", "10.0.5.255", "10.0.0.0/16", "10.0.5.0", "10.0.5.255"},
		// an answer that does not cover the netblock
		{"192.0.2.0/24", "192.0.3.0", "192.0.3.255", "", "", ""},
		// IPv6
		{"2001:db8:1::/48", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::/32", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		// mixed address families
		{"192.0.2.0/24", "2001:db8::", "2001:db8::ff", "", "", ""},
	} {
		got, start, end, ok := registeredPrefix(netip.MustParsePrefix(c.block),
			netip.MustParseAddr(c.start), netip.MustParseAddr(c.end))
		if c.want == "" {
			if ok {
				t.Errorf("%s %s-%s: got %s, want no prefix", c.block, c.start, c.end, got)
			}
			continue
		}
		if !ok || got.String() != c.want || start.String() != c.wantStart || end.String() != c.wantEnd {
			t.Errorf("%s %s-%s: got %s %s-%s (%v), want %s %s-%s", c.block, c.start, c.end,
				got, start, end, ok, c.want, c.wantStart, c.wantEnd)
		}
	}
}

// a /22 registration covering the announced /24s
const wideNetworkBody = `{"objectClassName":"ip network","handle":"NET-192-0-0-0-1",
	"startAddress":"192.0.0.0","endAddress":"192.0.3.255","ipVersion":"v4","name":"WIDE-NET",
	"type":"ASSIGNMENT","events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"},
	{"eventAction":"last changed","eventDate":"2026-01-01T00:00:00Z"}]}`

func registrationOf(t *testing.T, e *et.Event) *dbt.Entity {
	t.Helper()
	edges, err := e.Session.DB().OutgoingEdges(context.Background(), e.Entity, time.Time{}, "registration")
	if err != nil || len(edges) != 1 {
		t.Fatalf("netblock %s has %d registration edges (%v), want 1", e.Entity.Asset.Key(), len(edges), err)
	}
	rec, err := e.Session.DB().FindEntityById(context.Background(), edges[0].ToEntity.ID)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// RDAP answers a query for an announced /24 with the /22 registration
// covering it. The database requires a record's CIDR to contain its start
// and end addresses, so a record stored under the /24 was refused and lost.
// It is stored under the /22, every /24 it covers is linked to the one
// record, and a later lookup within the TTL follows the netblock's link.
func TestRDAPNetblockStoredUnderRegisteredRange(t *testing.T) {
	reg := &fakeRegistry{rdap: reply{200, wideNetworkBody}}
	p, e := newRDAPTest(t, reg, &network.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})

	if err := p.netblock.check(e); err != nil {
		t.Fatal(err)
	}
	if !marked(e, p.source) {
		t.Fatal("netblock not marked after a stored answer")
	}
	rec := registrationOf(t, e)
	r, ok := rec.Asset.(*oamreg.IPNetRecord)
	if !ok || r.CIDR.String() != "192.0.0.0/22" || r.Handle != "NET-192-0-0-0-1" {
		t.Fatalf("registration record = %#v, want NET-192-0-0-0-1 under 192.0.0.0/22", rec.Asset)
	}

	// a second /24 under the same registration shares the record
	sib, err := e.Session.DB().CreateAsset(context.Background(),
		&network.Netblock{CIDR: netip.MustParsePrefix("192.0.3.0/24"), Type: "IPv4"})
	if err != nil {
		t.Fatal(err)
	}
	e2 := &et.Event{Entity: sib, Session: e.Session, Dispatcher: e.Dispatcher}
	if err := p.netblock.check(e2); err != nil {
		t.Fatal(err)
	}
	if got := registrationOf(t, e2); got.ID != rec.ID {
		t.Errorf("sibling netblock linked to record %s, want the shared record %s", got.ID, rec.ID)
	}
	if !stored(e, oam.IPNetRecord, dbt.ContentFilters{"cidr": "192.0.0.0/22"}) {
		t.Error("no record stored under the registered range")
	}
	for _, cidr := range []string{"192.0.2.0/24", "192.0.3.0/24"} {
		if stored(e, oam.IPNetRecord, dbt.ContentFilters{"cidr": cidr}) {
			t.Errorf("a record was stored under the announced %s", cidr)
		}
	}

	// within the TTL the record is found by the netblock's own link
	queries := reg.queries
	if got := p.netblock.lookup(e, e.Entity, time.Now().Add(-time.Hour)); got == nil || got.ID != rec.ID {
		t.Errorf("lookup within the TTL = %v, want the linked record", got)
	}
	if err := p.netblock.check(e); err != nil {
		t.Fatal(err)
	}
	if reg.queries != queries {
		t.Errorf("made %d more RDAP queries within the TTL, want 0", reg.queries-queries)
	}
}

// A netblock marked as looked up but with no registration record to show
// for it (marked by a run that could not store the record) is queried again.
func TestRDAPNetblockMarkedWithoutRecordQueriedAgain(t *testing.T) {
	reg := &fakeRegistry{rdap: reply{200, wideNetworkBody}}
	p, e := newRDAPTest(t, reg, &network.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})
	support.MarkAssetMonitored(e.Session, e.Entity, p.source)

	if err := p.netblock.check(e); err != nil {
		t.Fatal(err)
	}
	if reg.queries != 1 {
		t.Fatalf("made %d RDAP queries, want 1", reg.queries)
	}
	_ = registrationOf(t, e)
}

// An answer that cannot be stored does not mark the netblock, so it is
// queried again rather than skipped for the TTL.
func TestRDAPNetblockNotMarkedWhenRecordNotStored(t *testing.T) {
	const noDates = `{"objectClassName":"ip network","handle":"NET-192-0-2-0-1",
		"startAddress":"192.0.2.0","endAddress":"192.0.2.255","ipVersion":"v4","name":"TEST-NET"}`
	reg := &fakeRegistry{rdap: reply{200, noDates}}
	p, e := newRDAPTest(t, reg, &network.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})

	if err := p.netblock.check(e); err != nil {
		t.Fatal(err)
	}
	if marked(e, p.source) {
		t.Error("netblock marked although no record was stored")
	}
	if stored(e, oam.IPNetRecord, dbt.ContentFilters{"cidr": "192.0.2.0/24"}) {
		t.Error("a record was stored for an answer without dates")
	}
}

type scopeSet struct {
	et.Scope
	added map[string]bool
}

func (s *scopeSet) Add(a oam.Asset) bool {
	s.added[a.Key()] = true
	return true
}

type admitTestSession struct {
	*rdapTestSession
	id    uuid.UUID
	scope *scopeSet
}

func (s *admitTestSession) ID() uuid.UUID   { return s.id }
func (s *admitTestSession) Scope() et.Scope { return s.scope }

// When a registration record is stored, the netblocks linked to it are
// admitted if its contacts attribute it to a seed, and not otherwise.
func TestAdmitParentNetblocksOfOwnedRecord(t *testing.T) {
	for _, c := range []struct {
		email string
		admit bool
	}{
		{"noc@target.com", true},
		{"noc@provider.example", false},
	} {
		t.Run(c.email, func(t *testing.T) {
			p, e := newRDAPTest(t, &fakeRegistry{}, &network.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})
			base := e.Session.(*rdapTestSession)
			base.cfg.AddDomains("target.com")
			sess := &admitTestSession{rdapTestSession: base, id: uuid.New(), scope: &scopeSet{added: map[string]bool{}}}
			defer support.ForgetSession(sess)

			ctx := context.Background()
			db := base.db
			create := func(a oam.Asset) *dbt.Entity {
				ent, err := db.CreateAsset(ctx, a)
				if err != nil || ent == nil {
					t.Fatalf("failed to create %T: %v", a, err)
				}
				return ent
			}
			link := func(label string, from, to *dbt.Entity) {
				if _, err := db.CreateEdge(ctx, &dbt.Edge{
					Relation: &general.SimpleRelation{Name: label}, FromEntity: from, ToEntity: to,
				}); err != nil {
					t.Fatal(err)
				}
			}

			rec := create(&oamreg.IPNetRecord{
				CIDR: netip.MustParsePrefix("192.0.0.0/22"), Handle: "NET-192-0-0-0-1", Type: "IPv4", Name: "WIDE-NET",
				StartAddress: netip.MustParseAddr("192.0.0.0"), EndAddress: netip.MustParseAddr("192.0.3.255"),
				CreatedDate: "2000-01-01T00:00:00Z", UpdatedDate: "2026-01-01T00:00:00Z",
			})
			sib := create(&network.Netblock{CIDR: netip.MustParsePrefix("192.0.3.0/24"), Type: "IPv4"})
			link("registration", e.Entity, rec)
			link("registration", sib, rec)
			cr := create(&contact.ContactRecord{DiscoveredAt: "https://rdap.test/entity/WIDE"})
			link("technical_contact", rec, cr)
			link("id", cr, create(&general.Identifier{UniqueID: "email:" + c.email, ID: c.email, Type: general.EmailAddress}))

			r := &ipnet{name: p.name + "-IPNetRecord-Handler", plugin: p}
			r.admitParentNetblock(&et.Event{Entity: rec, Session: sess, Dispatcher: e.Dispatcher}, rec)

			for _, cidr := range []string{"192.0.2.0/24", "192.0.3.0/24"} {
				if got := sess.scope.added[cidr]; got != c.admit {
					t.Errorf("%s admitted = %v, want %v", cidr, got, c.admit)
				}
			}
		})
	}
}
