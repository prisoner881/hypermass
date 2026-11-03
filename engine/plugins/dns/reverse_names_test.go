// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// The forward DNS handlers do not look up reverse DNS names: DNS-Reverse
// creates an FQDN for each address's in-addr.arpa name, and the A/AAAA,
// CNAME, TXT and subdomain lookups on it found nothing, three failed
// lookups per address in a zone that does not answer.
func TestForwardHandlersSkipReverseNames(t *testing.T) {
	rt := newReverseTest(t)
	p := NewDNS().(*dnsPlugin)
	ent := rt.asset(&oamdns.FQDN{Name: "10.153.123.74.in-addr.arpa"})
	e := &et.Event{Name: "10.153.123.74.in-addr.arpa", Entity: ent, Session: rt.sess}

	for name, check := range map[string]func(*et.Event) error{
		"DNS-IP":         (&dnsIP{name: "DNS-IP", plugin: p, source: p.source}).check,
		"DNS-CNAME":      (&dnsCNAME{name: "DNS-CNAME", plugin: p, source: p.source}).check,
		"DNS-TXT":        (&dnsTXT{name: "DNS-TXT", plugin: p, source: p.source}).check,
		"DNS-Subdomains": (&dnsSubs{name: "DNS-Subdomains", plugin: p}).check,
	} {
		start := time.Now()
		if err := check(e); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("%s took %v on a reverse name, want an immediate return", name, took)
		}
	}
	edges, err := rt.sess.db.OutgoingEdges(context.Background(), ent, time.Time{})
	if err == nil && len(edges) > 0 {
		t.Errorf("forward lookups stored %d records for a reverse name", len(edges))
	}
}

type nopDispatcher struct{ et.Dispatcher }

func (nopDispatcher) DispatchEvent(*et.Event) error { return nil }

// DNS-Reverse does not look up an address whose network's reverse zone
// has stopped answering this session.
func TestReverseSkipsBrokenZone(t *testing.T) {
	rt := newReverseTest(t)
	rt.sess.cfg.Transformations = map[string]*config.Transformation{
		"IPAddress->ALL": {From: "ipaddress", To: "all", TTL: 1440},
	}
	defer support.ForgetSession(rt.sess)
	for i := 0; i < support.BrokenReverseZoneFailures; i++ {
		support.RecordReverseLookup(rt.sess, netip.MustParseAddr("74.123.153.1"), true)
	}

	ipEnt := rt.asset(&oamnet.IPAddress{Address: netip.MustParseAddr("74.123.153.77"), Type: "IPv4"})
	start := time.Now()
	if err := rt.rev.check(&et.Event{Entity: ipEnt, Session: rt.sess, Dispatcher: nopDispatcher{}}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("took %v, want an immediate return", took)
	}
	ents, err := rt.sess.db.FindEntitiesByContent(context.Background(), oam.FQDN, time.Time{}, 1,
		dbt.ContentFilters{"name": "77.153.123.74.in-addr.arpa"})
	if err == nil && len(ents) > 0 {
		t.Error("the reverse name was created for an address in a broken zone")
	}
}
