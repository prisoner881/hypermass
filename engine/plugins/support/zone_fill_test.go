// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

func TestForwardZone(t *testing.T) {
	for name, want := range map[string]string{
		"host12.ad.med.buffalo.edu":     "ad.med.buffalo.edu",
		"dhcp-1-2.wireless.buffalo.edu": "wireless.buffalo.edu",
		"www.buffalo.edu":               "", // the zone is the registered domain
		"buffalo.edu":                   "",
		"edu":                           "",
		"a.b.example.co.uk.":            "b.example.co.uk",
		"www.example.co.uk":             "",
		"10.153.123.74.in-addr.arpa":    "",
	} {
		if got := ForwardZone(name); got != want {
			t.Errorf("ForwardZone(%q) = %q, want %q", name, got, want)
		}
	}
}

// A zone counts as broken after lookups of BrokenForwardZoneNames distinct
// names failed with none answered; one answer keeps it open; a registered
// domain never counts as broken.
func TestBrokenForwardZones(t *testing.T) {
	sess, _ := newP1Session(t, "enforce")
	defer ForgetSession(sess)

	// the same name failing again does not count twice
	for i := 0; i < 3*BrokenForwardZoneNames; i++ {
		RecordForwardLookup(sess, "host1.ad.med.buffalo.edu", true)
	}
	if ForwardZoneBroken(sess, "host2.ad.med.buffalo.edu") {
		t.Fatal("broken after one name failed repeatedly")
	}
	for i := 2; i <= BrokenForwardZoneNames; i++ {
		zone, now := RecordForwardLookup(sess, fmt.Sprintf("host%d.ad.med.buffalo.edu", i), true)
		if zone != "ad.med.buffalo.edu" {
			t.Fatalf("zone = %q", zone)
		}
		if now != (i == BrokenForwardZoneNames) {
			t.Errorf("name %d reported broken = %v", i, now)
		}
	}
	if !ForwardZoneBroken(sess, "other.ad.med.buffalo.edu") {
		t.Error("the zone is not broken after its names failed")
	}
	if ForwardZoneBroken(sess, "host1.ad.sdm.buffalo.edu") || ForwardZoneBroken(sess, "www.buffalo.edu") {
		t.Error("another zone, or the registered domain, counts as broken")
	}

	// an answered lookup ("no such name" included) keeps a zone open
	RecordForwardLookup(sess, "vpn1.cit.buffalo.edu", false)
	for i := 0; i < 2*BrokenForwardZoneNames; i++ {
		RecordForwardLookup(sess, fmt.Sprintf("h%d.cit.buffalo.edu", i), true)
	}
	if ForwardZoneBroken(sess, "h99.cit.buffalo.edu") {
		t.Error("a zone that answered a lookup counts as broken")
	}

	// the registered domain is never tracked
	for i := 0; i < 2*BrokenForwardZoneNames; i++ {
		RecordForwardLookup(sess, fmt.Sprintf("h%d.buffalo.edu", i), true)
	}
	if ForwardZoneBroken(sess, "www.buffalo.edu") {
		t.Error("the registered domain counts as broken")
	}
}

// fullBacklog reports a full IPAddress backlog for its first full checks.
type fullBacklog struct {
	et.Backlog
	full  int32
	calls atomic.Int32
}

func (b *fullBacklog) Counts(oam.AssetType) (int64, int64, int64, error) {
	if b.calls.Add(1) <= b.full {
		return ownedFillMaxBacklog, 0, 0, nil
	}
	return 0, 0, 0, nil
}

type fillSession struct {
	*p1Session
	ctx     context.Context
	backlog et.Backlog
}

func (s *fillSession) Ctx() context.Context { return s.ctx }
func (s *fillSession) Backlog() et.Backlog  { return s.backlog }
func (s *fillSession) Done() bool           { return s.ctx.Err() != nil }

// A fill waits while the IPAddress backlog is full, and still fills every
// address.
func TestOwnedFillPacedByBacklog(t *testing.T) {
	old := fillPauseInterval
	fillPauseInterval = time.Millisecond
	defer func() { fillPauseInterval = old }()

	base, logs := newP1Session(t, "enforce")
	b := &fullBacklog{full: 3}
	s := &fillSession{p1Session: base, ctx: context.Background(), backlog: b}

	pfx := netip.MustParsePrefix("203.0.113.0/30")
	nb := &oamnet.Netblock{CIDR: pfx, Type: "IPv4"}
	nbEnt := mustCreate(t, base.db, nb)
	fillOwnedNetblock(s, nil, nbEnt, nb)

	if got := b.calls.Load(); got < 4 {
		t.Errorf("backlog checked %d times, want the fill to wait through 3 full checks", got)
	}
	for _, a := range []string{"203.0.113.1", "203.0.113.2"} {
		ents, err := base.db.FindEntitiesByContent(context.Background(), oam.IPAddress, time.Time{}, 1,
			dbt.ContentFilters{"address": a})
		if err != nil || len(ents) == 0 {
			t.Errorf("%s was not filled", a)
		}
	}
	out := logs.String()
	if n := strings.Count(out, "owned-netblock fill paused"); n != 1 {
		t.Errorf("pause logged %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "created=2") || !strings.Contains(out, "paused=1") {
		t.Errorf("fill summary lacks the counts:\n%s", out)
	}
}

// A fill waiting on a full backlog stops when the session ends.
func TestOwnedFillStopsWhenSessionEndsWhilePaused(t *testing.T) {
	old := fillPauseInterval
	fillPauseInterval = time.Millisecond
	defer func() { fillPauseInterval = old }()

	base, _ := newP1Session(t, "enforce")
	ctx, cancel := context.WithCancel(context.Background())
	s := &fillSession{p1Session: base, ctx: ctx, backlog: &fullBacklog{full: 1 << 30}}

	nb := &oamnet.Netblock{CIDR: netip.MustParsePrefix("203.0.113.4/30"), Type: "IPv4"}
	nbEnt := mustCreate(t, base.db, nb)
	done := make(chan struct{})
	go func() { fillOwnedNetblock(s, nil, nbEnt, nb); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the paused fill did not stop when the session ended")
	}
}

type ipScope struct{ et.Scope }

func (ipScope) IsAssetInScope(a oam.Asset, _ int) (oam.Asset, int) { return a, 100 }

type noopSemaphore struct{}

func (noopSemaphore) Acquire()   {}
func (noopSemaphore) Release()   {}
func (noopSemaphore) InUse() int { return 0 }
func (noopSemaphore) Cap() int   { return 1 }

type scanSession struct {
	*p1Session
}

func (s *scanSession) Scope() et.Scope              { return ipScope{} }
func (s *scanSession) ScanSem() et.SessionSemaphone { return noopSemaphore{} }

// No address in a network without a BGP route is port scanned.
func TestPortScanSkipsUnroutedAddress(t *testing.T) {
	base, _ := newP1Session(t, "enforce")
	base.cfg.Scope.Ports = []int{80, 443}
	base.cfg.Transformations = map[string]*config.Transformation{
		"IPAddress->ALL": {From: "ipaddress", To: "all", TTL: 1440},
	}
	sess := &scanSession{p1Session: base}
	defer ForgetSession(sess)

	var mu sync.Mutex
	var dialed []string
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return nil, errors.New("refused")
	}

	RecordUnrouted(sess, netip.MustParseAddr("8.35.168.1"))
	ent := mustCreate(t, base.db, &oamnet.IPAddress{Address: netip.MustParseAddr("8.35.168.10"), Type: "IPv4"})
	if ports := EnsureOpenPortsScanned(&et.Event{Entity: ent, Session: sess}, ent, dial); len(ports) != 0 {
		t.Errorf("ports %v reported for an unrouted address", ports)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 0 {
		t.Errorf("dialed %v for an address in an unrouted network", dialed)
	}
}
