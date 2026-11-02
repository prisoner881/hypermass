// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// addScope counts additions on top of fakeScope.
type addScope struct {
	*fakeScope
	mu    sync.Mutex
	added []string
}

func (s *addScope) Add(a oam.Asset) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.added = append(s.added, a.Key())
	return true
}

type admitSession struct {
	*p1Session
	scope *addScope
}

func (s *admitSession) Scope() et.Scope { return s.scope }

// A netblock is attributed once per session: the check runs for every
// address in the block, and only the first walks the registration, adds the
// block to scope and logs it, one step from the seed domain the contact
// email is on. The registration may be larger than the netblock.
func TestAdmitOwnedNetblockOncePerSession(t *testing.T) {
	base, logs := newP1Session(t, "enforce")
	sess := &admitSession{p1Session: base, scope: &addScope{fakeScope: base.scope}}

	nb := mustCreate(t, base.db, &oamnet.Netblock{CIDR: netip.MustParsePrefix("203.0.113.0/24"), Type: "IPv4"})
	rec := mustCreate(t, base.db, &oamreg.IPNetRecord{
		CIDR: netip.MustParsePrefix("203.0.112.0/22"), Handle: "NET-203-0-112-0-1", Type: "IPv4", Name: "TARGET-NET",
		StartAddress: netip.MustParseAddr("203.0.112.0"), EndAddress: netip.MustParseAddr("203.0.115.255"),
		CreatedDate: "2020-01-01T00:00:00Z", UpdatedDate: "2024-01-01T00:00:00Z",
	})
	mustEdge(t, base.db, "registration", nb, rec)
	cr := mustCreate(t, base.db, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.test/entity/TARGET"})
	mustEdge(t, base.db, "technical_contact", rec, cr)
	mustEdge(t, base.db, "id", cr, mustCreate(t, base.db, &general.Identifier{
		UniqueID: "email:noc@target.com", ID: "noc@target.com", Type: general.EmailAddress}))

	e := &et.Event{Entity: nb, Session: sess}
	for i := 0; i < 3; i++ {
		if !AdmitOwnedNetblock(e, nb) {
			t.Fatalf("call %d: netblock not attributed", i+1)
		}
	}

	if len(sess.scope.added) != 1 {
		t.Errorf("added to scope %d times, want 1", len(sess.scope.added))
	}
	if n := strings.Count(logs.String(), "netblock attributed to seed via RDAP contact"); n != 1 {
		t.Errorf("attribution logged %d times, want 1", n)
	}
	if d := ScopeDistance(sess, nb.Asset); d != 1 {
		t.Errorf("distance = %d, want 1", d)
	}
	if !strings.Contains(logs.String(), "distance=1") {
		t.Errorf("attribution log lacks the distance:\n%s", logs.String())
	}

	// a new session checks again
	other := &admitSession{p1Session: &p1Session{id: uuid.New(), db: base.db, cfg: base.cfg, scope: base.scope, log: base.log},
		scope: &addScope{fakeScope: base.scope}}
	if !AdmitOwnedNetblock(&et.Event{Entity: nb, Session: other}, nb) || len(other.scope.added) != 1 {
		t.Errorf("a second session did not attribute the netblock")
	}
	ForgetSession(sess)
	ForgetSession(other)
}

// Scope matches an organization by name, and several Organization entities
// can carry the same name: each has the distance recorded for the name.
func TestOrganizationDistanceByName(t *testing.T) {
	sess, _ := newP1Session(t, "enforce")
	defer ForgetSession(sess)

	first := &oamorg.Organization{ID: uuid.NewString(), Name: "Target Corp"}
	second := &oamorg.Organization{ID: uuid.NewString(), Name: "target corp"}
	if d := RecordScopeAddition(sess, first, &oamdns.FQDN{Name: "target.com"}); d != 1 {
		t.Fatalf("recorded distance = %d, want 1", d)
	}
	if d := ScopeDistance(sess, second); d != 1 {
		t.Errorf("distance of another entity with the same name = %d, want 1", d)
	}
	if d := ScopeDistance(sess, &oamorg.Organization{ID: uuid.NewString(), Name: "Other Corp"}); d != -1 {
		t.Errorf("distance of an unrelated organization = %d, want -1", d)
	}
}
