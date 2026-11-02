// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
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

// recBacklog records the entities queued for processing.
type recBacklog struct {
	et.Backlog
	mu  sync.Mutex
	ids []string
}

func (b *recBacklog) Enqueue(e *dbt.Entity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ids = append(b.ids, e.ID)
	return nil
}

func (b *recBacklog) queued(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, v := range b.ids {
		if v == id {
			return true
		}
	}
	return false
}

type enqueueTestSession struct {
	ownerTestSession
	backlog *recBacklog
}

func (s *enqueueTestSession) Backlog() et.Backlog { return s.backlog }

func newEnqueueTestSession(t *testing.T) (*enqueueTestSession, func(oam.Asset) *dbt.Entity, func(string, *dbt.Entity, *dbt.Entity)) {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.AddDomains("target.com")
	cfg.Transformations = map[string]*config.Transformation{}
	for _, from := range []string{"domainrecord", "contactrecord", "organization", "location", "fqdn", "tlscertificate"} {
		cfg.Transformations[from+"->all"] = &config.Transformation{From: from, To: "all", TTL: 1440, Confidence: 50}
	}

	sess := &enqueueTestSession{
		ownerTestSession: ownerTestSession{id: uuid.New(), db: db, cfg: cfg, scope: &setScope{set: map[string]struct{}{}}},
		backlog:          &recBacklog{},
	}
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
	return sess, create, edge
}

// A domain whose registrant organization is in scope joins the scope, and
// its domain name, not its registration record, is queued, so the work done
// only for in-scope names runs on it.
func TestDomainRecordQueuesTheDomainName(t *testing.T) {
	sess, create, edge := newEnqueueTestSession(t)

	fqdn := create(&oamdns.FQDN{Name: "sub-co.com"})
	dr := create(&oamreg.DomainRecord{Domain: "sub-co.com", Name: "sub-co.com", ID: "D1"})
	cr := create(&oamcon.ContactRecord{DiscoveredAt: "whois.example, sub-co.com, Registrant Contact Info"})
	org := create(&oamorg.Organization{ID: uuid.NewString(), Name: "Target Corp"})
	edge("registrant_contact", dr, cr)
	edge("organization", cr, org)
	sess.scope.Add(org.Asset)

	h := &horRegRec{name: "Horizontals-Registration-Record-Handler", plugin: NewHorizontals().(*horizPlugin)}
	if err := h.check(&et.Event{Name: "sub-co.com", Entity: dr, Session: sess}); err != nil {
		t.Fatal(err)
	}

	if !sess.scope.has(&oamdns.FQDN{Name: "sub-co.com"}) {
		t.Fatal("sub-co.com: want in scope")
	}
	if !sess.backlog.queued(fqdn.ID) {
		t.Errorf("want the FQDN sub-co.com queued, got %v", sess.backlog.ids)
	}
	if sess.backlog.queued(dr.ID) {
		t.Error("the registration record was queued instead of the domain name")
	}
}

// A certificate reached through an in-scope organization or address adds
// the registered domain of its common name, which is usually a host name.
func TestCertificateQueuesItsRegisteredDomain(t *testing.T) {
	sess, create, _ := newEnqueueTestSession(t)

	fqdn := create(&oamdns.FQDN{Name: "sub-co.com"})
	cert := create(&oamcert.TLSCertificate{
		Version: "3", SerialNumber: "0a1b2c", SubjectCommonName: "www.sub-co.com", IssuerCommonName: "Test CA",
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
	})

	h := NewHorizontals().(*horizPlugin)
	h.enqueueCertificateDomain(sess, cert, nil, "certificate")

	if !sess.scope.has(&oamdns.FQDN{Name: "sub-co.com"}) {
		t.Fatal("sub-co.com: want in scope")
	}
	if !sess.backlog.queued(fqdn.ID) {
		t.Errorf("want the FQDN sub-co.com queued, got %v", sess.backlog.ids)
	}
}
