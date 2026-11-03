// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/netip"
	"testing"

	"github.com/google/uuid"
)

func TestIsReverseDNSName(t *testing.T) {
	for name, want := range map[string]bool{
		"10.153.123.74.in-addr.arpa":       true,
		"135.153.123.74.in-addr.arpa.":     true,
		"153.123.74.IN-ADDR.ARPA":          true,
		"1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa": true,
		"in-addr.arpa":                     true,
		"www.blackbaud.com":                false,
		"arpa":                             false,
		"in-addr.arpa.example.com":         false,
		"notin-addr.arpa":                  false,
	} {
		if got := IsReverseDNSName(name); got != want {
			t.Errorf("IsReverseDNSName(%q) = %v, want %v", name, got, want)
		}
	}
}

// A /24 whose PTR lookups all fail counts as broken after
// BrokenReverseZoneFailures of them; one answered lookup keeps it open.
func TestBrokenReverseZones(t *testing.T) {
	sess, _ := newP1Session(t, "enforce")
	other := &p1Session{id: uuid.New(), db: sess.db, cfg: sess.cfg, scope: sess.scope, log: sess.log}
	defer ForgetSession(other)

	broken := netip.MustParseAddr("74.123.153.10")
	for i := 1; i <= BrokenReverseZoneFailures; i++ {
		if ReverseZoneBroken(sess, broken) {
			t.Fatalf("broken after %d failures, want %d", i-1, BrokenReverseZoneFailures)
		}
		p, now := RecordReverseLookup(sess, netip.MustParseAddr("74.123.153."+string(rune('0'+i))), true)
		if p.String() != "74.123.153.0/24" {
			t.Fatalf("network = %s, want 74.123.153.0/24", p)
		}
		if now != (i == BrokenReverseZoneFailures) {
			t.Errorf("failure %d reported broken = %v", i, now)
		}
	}
	if !ReverseZoneBroken(sess, netip.MustParseAddr("74.123.153.250")) {
		t.Error("the /24 is not broken after its failures")
	}
	if _, now := RecordReverseLookup(sess, broken, true); now {
		t.Error("a further failure reported the zone newly broken again")
	}
	if ReverseZoneBroken(sess, netip.MustParseAddr("74.123.154.1")) {
		t.Error("another /24 counts as broken")
	}
	if ReverseZoneBroken(other, broken) {
		t.Error("another session sees this session's broken zones")
	}

	// an answered lookup (a PTR record, no such name, no PTR) keeps a zone open
	RecordReverseLookup(sess, netip.MustParseAddr("209.67.132.1"), false)
	for i := 0; i < 2*BrokenReverseZoneFailures; i++ {
		RecordReverseLookup(sess, netip.MustParseAddr("209.67.132.2"), true)
	}
	if ReverseZoneBroken(sess, netip.MustParseAddr("209.67.132.3")) {
		t.Error("a zone that answered a lookup counts as broken")
	}

	ForgetSession(sess)
	if ReverseZoneBroken(sess, broken) {
		t.Error("broken zones kept after the session ended")
	}
}
