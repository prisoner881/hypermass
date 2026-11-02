// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// failNamesDB fails CreateAsset for the chosen FQDNs.
type failNamesDB struct {
	repository.Repository
	fail map[string]bool
}

func (f *failNamesDB) CreateAsset(ctx context.Context, a oam.Asset) (*dbt.Entity, error) {
	if n, ok := a.(*oamdns.FQDN); ok && f.fail[n.Name] {
		return nil, errors.New("simulated database failure")
	}
	return f.Repository.CreateAsset(ctx, a)
}

// A large IP-THC answer is stored in full and the lookup marked.
func TestTHCLargeAnswerStoredAndMarked(t *testing.T) {
	var b strings.Builder
	b.WriteString("domain\n")
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "host%d.example.com\n", i)
	}
	p := NewIPTHC().(*ipTHC)
	p.log = discardLog()
	e, _ := newMarkTestEvent(t, ok200(b.String()), ok200("domain\n"))

	if err := p.checkFQDN(e); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"host0.example.com", "host250.example.com", "host499.example.com"} {
		if !storedFQDN(t, e, n) {
			t.Errorf("%s not stored", n)
		}
	}
	if !marked(e, p.source) {
		t.Error("lookup not marked after every name was stored")
	}
}

// An IP-THC lookup whose names could not all be stored is left unmarked,
// so it is retried rather than skipped for the TTL. The names that were
// stored are kept.
func TestTHCLookupNotMarkedWhenNamesNotStored(t *testing.T) {
	p := NewIPTHC().(*ipTHC)
	p.log = discardLog()
	e, _ := newMarkTestEvent(t, ok200("domain\nwww.example.com\nmail.example.com\n"), ok200("domain\n"))
	s := e.Session.(*markTestSession)
	s.db = &failNamesDB{Repository: s.db, fail: map[string]bool{"mail.example.com": true}}

	if err := p.checkFQDN(e); err != nil {
		t.Fatal(err)
	}
	if marked(e, p.source) {
		t.Error("lookup marked although a name was not stored")
	}
	if !storedFQDN(t, e, "www.example.com") {
		t.Error("the name that could be stored was not kept")
	}
}
