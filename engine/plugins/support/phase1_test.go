// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// fakeScope holds in-scope organizations by exact name and domains by suffix.
type fakeScope struct {
	et.Scope
	orgs    map[string]bool
	domains []string
}

func (s *fakeScope) IsAssetInScope(a oam.Asset, _ int) (oam.Asset, int) {
	switch v := a.(type) {
	case *oamorg.Organization:
		if s.orgs[strings.ToLower(v.Name)] {
			return a, 100
		}
	case *oamdns.FQDN:
		for _, d := range s.domains {
			if v.Name == d || strings.HasSuffix(v.Name, "."+d) {
				return a, 100
			}
		}
	}
	return nil, 0
}

type p1Session struct {
	et.Session
	id    uuid.UUID
	db    repository.Repository
	cfg   *config.Config
	scope *fakeScope
	log   *slog.Logger
}

func (s *p1Session) ID() uuid.UUID             { return s.id }
func (s *p1Session) Ctx() context.Context      { return context.Background() }
func (s *p1Session) Log() *slog.Logger         { return s.log }
func (s *p1Session) Config() *config.Config    { return s.cfg }
func (s *p1Session) DB() repository.Repository { return s.db }
func (s *p1Session) Scope() et.Scope           { return s.scope }

// syncBuffer collects log output from concurrent writers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newP1Session(t *testing.T, mode string) (*p1Session, *syncBuffer) {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	id := uuid.New()
	cfg := config.NewConfig()
	cfg.AddDomains("target.com")
	cfg.ScopeVetoes = mode
	cfg.GraphDBs = []*config.Database{{System: "sqlite", Primary: true, DBName: id.String()}}
	logs := &syncBuffer{}
	return &p1Session{
		id: id, db: db, cfg: cfg,
		scope: &fakeScope{orgs: map[string]bool{"target corp": true}, domains: []string{"target.com"}},
		log:   slog.New(slog.NewTextHandler(logs, nil)),
	}, logs
}

func mustCreate(t *testing.T, db repository.Repository, a oam.Asset) *dbt.Entity {
	t.Helper()
	ent, err := db.CreateAsset(context.Background(), a)
	if err != nil || ent == nil {
		t.Fatalf("failed to create %T: %v", a, err)
	}
	return ent
}

func mustEdge(t *testing.T, db repository.Repository, label string, from, to *dbt.Entity) {
	t.Helper()
	if _, err := db.CreateEdge(context.Background(), &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	}); err != nil {
		t.Fatal(err)
	}
}

// Addresses from the testing database's shared-address export.
func TestIsCareOfOrMailDrop(t *testing.T) {
	for _, s := range []string{
		"C/O THE CORPORATION TRUST COMPANY CORPORATION TRUST CENTER 1209 ORANGE ST WILMINGTON DE 19801 US",
		"C/O REGISTERED AGENT SOLUTIONS, INC. 838 WALKER ROAD SUITE 21-2 DOVER DE 19904 US",
		"5335 Gate Parkway care of Network Solutions PO Box 459 Jacksonville FL 32256 US",
		"Super Privacy Service LTD c/o Dynadot PO Box 701 San Mateo California 94401 US",
		"c/o IDPS International Domain Privacy Services GmbH, Hansaallee 191 Duesseldorf",
		"1928 E. Highland Ave. Ste F104 PMB# 255 Phoenix AZ 85016 US",
		"1235 East Blvd Suite E PMB 5086 Charlotte North Carolina 28203 US",
		"Knock Knock WHOIS Not There, LLC 9450 SW Gemini Dr #63259 Beaverton 97008-7105 US",
	} {
		if !IsCareOfOrMailDrop(s) {
			t.Errorf("%q: want care-of or mail drop", s)
		}
	}
	for _, s := range []string{
		"", "Gullhaug Torg 5 Oslo 0484 NO", "415 Mission Street, 3rd Floor San Francisco CA 94105",
		"100 S. Mill Ave, Suite 1600 Tempe Arizona 85281", "Coastal Highway Suite #300", "Acme Corp",
		"Cocoa Beach FL", "Echo Park, Los Angeles",
	} {
		if IsCareOfOrMailDrop(s) {
			t.Errorf("%q: want an ordinary address", s)
		}
	}
}

func TestDeclineModes(t *testing.T) {
	for _, c := range []struct {
		mode, action string
		block        bool
	}{
		{"", "declined", true},
		{"enforce", "declined", true},
		{"observe", "would decline", false},
		{"off", "", false},
		{"bogus", "declined", true}, // unrecognized means enforce
	} {
		sess, logs := newP1Session(t, c.mode)
		for i := 0; i < 2; i++ {
			if got := Decline(sess, VetoResolutionOnly, "Netblock", "104.18.16.0/20", "test", "asn", 13335); got != c.block {
				t.Errorf("mode %q: Decline = %v, want %v", c.mode, got, c.block)
			}
		}
		out := logs.String()
		if c.action == "" {
			if out != "" {
				t.Errorf("mode off: want nothing logged, got %s", out)
			}
			continue
		}
		if n := strings.Count(out, "scope decision"); n != 1 {
			t.Errorf("mode %q: want one log line, got %d: %s", c.mode, n, out)
		}
		action := "action=" + c.action
		if strings.Contains(c.action, " ") {
			action = "action=\"" + c.action + "\""
		}
		if !strings.Contains(out, action) || !strings.Contains(out, "asn=13335") {
			t.Errorf("mode %q: want action %q and evidence logged, got %s", c.mode, c.action, out)
		}
	}
}

func TestScopeDistance(t *testing.T) {
	sess, _ := newP1Session(t, "")
	seed := &oamdns.FQDN{Name: "www.target.com"}
	if d := ScopeDistance(sess, seed); d != 0 {
		t.Fatalf("seed: distance %d, want 0", d)
	}
	org := &oamorg.Organization{ID: "1", Name: "Target Corp"}
	if d := RecordScopeAddition(sess, org, seed); d != 1 {
		t.Fatalf("org from seed: distance %d, want 1", d)
	}
	other := &oamdns.FQDN{Name: "sub-co.com"}
	if d := RecordScopeAddition(sess, other, org); d != 2 {
		t.Fatalf("domain from org: distance %d, want 2", d)
	}
	// a registration record counts as what it registers
	if d := ScopeDistance(sess, &oamreg.DomainRecord{Domain: "sub-co.com"}); d != 2 {
		t.Errorf("domain record: distance %d, want 2", d)
	}
	// the shortest route is kept
	if d := RecordScopeAddition(sess, other, seed); d != 1 || ScopeDistance(sess, other) != 1 {
		t.Errorf("shorter route: distance %d, want 1", d)
	}
	// unknown origin
	if d := RecordScopeAddition(sess, &oamdns.FQDN{Name: "x.com"}, nil); d != -1 {
		t.Errorf("unknown origin: distance %d, want -1", d)
	}
	ForgetSession(sess)
	if d := ScopeDistance(sess, other); d != -1 {
		t.Errorf("after ForgetSession: distance %d, want -1", d)
	}
}

func TestRangeToPrefixes(t *testing.T) {
	for _, c := range []struct {
		start, end string
		want       []string
	}{
		{"198.51.100.0", "198.51.100.255", []string{"198.51.100.0/24"}},
		{"198.51.100.32", "198.51.100.63", []string{"198.51.100.32/27"}},
		{"198.51.100.0", "198.51.100.5", []string{"198.51.100.0/30", "198.51.100.4/31"}},
		{"198.51.100.7", "198.51.100.7", []string{"198.51.100.7/32"}},
		{"2001:db8::", "2001:db8::ffff:ffff:ffff:ffff", []string{"2001:db8::/64"}},
	} {
		got := RangeToPrefixes(netip.MustParseAddr(c.start), netip.MustParseAddr(c.end), 8)
		var gs []string
		for _, p := range got {
			gs = append(gs, p.String())
		}
		if strings.Join(gs, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s-%s: got %v, want %v", c.start, c.end, gs, c.want)
		}
	}
	// too many blocks, and an inverted range
	if p := RangeToPrefixes(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.254"), 8); p != nil {
		t.Errorf("1-254: want nil (too many blocks), got %v", p)
	}
	if p := RangeToPrefixes(netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("198.51.100.1"), 8); p != nil {
		t.Errorf("inverted: want nil, got %v", p)
	}
}

// The blue.cl case: Salesforce's and Cloudflare's blocks are registered to
// them, so their registrations are foreign to the target.
func TestRegistrationVerdict(t *testing.T) {
	sess, _ := newP1Session(t, "")
	ctx := context.Background()

	var n byte
	record := func(handle, registrant string, emails ...string) *dbt.Entity {
		n++ // each record needs its own block
		block := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, n, 0}), 24)
		rec := mustCreate(t, sess.db, &oamreg.IPNetRecord{
			CIDR: block, Handle: handle, Type: "IPv4", Name: handle,
			StartAddress: block.Addr(), EndAddress: lastAddr(block),
		})
		cr := mustCreate(t, sess.db, &oamcon.ContactRecord{DiscoveredAt: "rdap " + handle + " registrant"})
		mustEdge(t, sess.db, "registrant", rec, cr)
		if registrant != "" {
			mustEdge(t, sess.db, "organization", cr, mustCreate(t, sess.db, &oamorg.Organization{ID: uuid.NewString(), Name: registrant}))
		}
		for i, email := range emails {
			poc := mustCreate(t, sess.db, &oamcon.ContactRecord{DiscoveredAt: "rdap " + handle + " poc " + email})
			mustEdge(t, sess.db, []string{"abuse_contact", "technical_contact"}[i%2], rec, poc)
			mustEdge(t, sess.db, "id", poc, mustCreate(t, sess.db, &general.Identifier{
				UniqueID: "email:" + email, ID: email, Type: general.EmailAddress}))
		}
		return rec
	}

	for _, c := range []struct {
		name string
		rec  *dbt.Entity
		want Verdict
	}{
		{"Salesforce", record("NET-SALESF", "Salesforce, Inc.", "abuse@salesforce.com"), VerdictForeign},
		{"Cloudflare", record("NET-CLOUDFLARE", "Cloudflare, Inc.", "abuse@cloudflare.com", "noc@cloudflare.com"), VerdictForeign},
		{"target email", record("NET-T1", "Target Corp", "noc@target.com"), VerdictOwner},
		{"target email, other registrant", record("NET-T2", "Some ISP", "abuse@isp.example", "hostmaster@target.com"), VerdictOwner},
		{"registrant in scope", record("NET-T3", "Target Corp", "abuse@isp.example"), VerdictOwner},
		{"freemail only", record("NET-F", "Joe's Bakery", "joe@gmail.com"), VerdictNoInfo},
		{"placeholder registrant", record("NET-P", "Domain Administrator", "abuse@isp.example"), VerdictNoInfo},
		{"no contacts", mustCreate(t, sess.db, &oamreg.IPNetRecord{
			CIDR: netip.MustParsePrefix("198.51.100.0/24"), Handle: "NET-EMPTY", Type: "IPv4", Name: "NET-EMPTY",
			StartAddress: netip.MustParseAddr("198.51.100.0"), EndAddress: netip.MustParseAddr("198.51.100.255"),
		}), VerdictNoInfo},
	} {
		if got, ev := RegistrationVerdict(ctx, sess, c.rec); got != c.want {
			t.Errorf("%s: verdict %s, want %s (evidence %+v)", c.name, got, c.want, ev)
		}
	}
}

func TestIsMergedCertificate(t *testing.T) {
	sess, logs := newP1Session(t, "")
	ctx := context.Background()

	cert := func(serial string, cns []string, orgs []string) *dbt.Entity {
		c := mustCreate(t, sess.db, &oamcert.TLSCertificate{
			Version: "3", SerialNumber: serial, SubjectCommonName: cns[0], IssuerCommonName: "CA",
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
		})
		for _, cn := range cns {
			mustEdge(t, sess.db, "common_name", c, mustCreate(t, sess.db, &oamdns.FQDN{Name: cn}))
		}
		cr := mustCreate(t, sess.db, &oamcon.ContactRecord{DiscoveredAt: "x509 " + serial + " Subject"})
		mustEdge(t, sess.db, "subject_contact", c, cr)
		for _, o := range orgs {
			mustEdge(t, sess.db, "organization", cr, mustCreate(t, sess.db, &oamorg.Organization{ID: uuid.NewString(), Name: o}))
		}
		return c
	}

	single := cert("1a2b", []string{"www.target.com"}, []string{"Target Corp"})
	if IsMergedCertificate(ctx, sess, single) {
		t.Error("a genuine certificate: want not merged")
	}
	// one stored certificate for serial 1, from unrelated devices
	byNames := cert("1", []string{"router.acme.com", "nas.globex.net"}, nil)
	byOrgs := cert("0", []string{"device.local"}, []string{"Fortinet", "Acme", "Internet Widgits Pty Ltd", "Dell Inc."})
	for name, c := range map[string]*dbt.Entity{"two registered domains": byNames, "several organizations": byOrgs} {
		if !IsMergedCertificate(ctx, sess, c) {
			t.Errorf("%s: want merged", name)
		}
	}

	// scope association skips a merged certificate as evidence
	if scope.SkipAssociationEvidence == nil || !scope.SkipAssociationEvidence(sess, byOrgs) {
		t.Error("association hook: want a merged certificate skipped")
	}
	if scope.SkipAssociationEvidence(sess, single) {
		t.Error("association hook: want a genuine certificate kept")
	}
	if !strings.Contains(logs.String(), VetoMergedCertificate) {
		t.Errorf("want the decision logged, got %s", logs.String())
	}
}
