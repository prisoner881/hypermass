// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/netip"
	"testing"

	"github.com/google/uuid"
)

func TestUnroutedNetworks(t *testing.T) {
	sess, _ := newP1Session(t, "enforce")
	other := &p1Session{id: uuid.New(), db: sess.db, cfg: sess.cfg, scope: sess.scope, log: sess.log}
	defer ForgetSession(other)

	p, first := RecordUnrouted(sess, netip.MustParseAddr("216.235.193.104"))
	if !first || p.String() != "216.235.193.0/24" {
		t.Fatalf("recorded %s (new %v), want 216.235.193.0/24 newly recorded", p, first)
	}
	if _, first := RecordUnrouted(sess, netip.MustParseAddr("216.235.193.92")); first {
		t.Error("a second address in the same /24 was recorded as a new network")
	}
	for addr, want := range map[string]bool{
		"216.235.193.1":        true,  // same /24
		"216.235.194.1":        false, // the next /24, announced
		"::ffff:216.235.193.7": true,  // IPv4-mapped
	} {
		if got := KnownUnrouted(sess, netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s unrouted = %v, want %v", addr, got, want)
		}
	}
	if KnownUnrouted(other, netip.MustParseAddr("216.235.193.1")) {
		t.Error("another session sees this session's unrouted networks")
	}

	if p, _ := RecordUnrouted(sess, netip.MustParseAddr("2001:db8:1:2::5")); p.String() != "2001:db8:1::/48" {
		t.Errorf("IPv6 network = %s, want 2001:db8:1::/48", p)
	}
	if !KnownUnrouted(sess, netip.MustParseAddr("2001:db8:1:ffff::1")) || KnownUnrouted(sess, netip.MustParseAddr("2001:db8:2::1")) {
		t.Error("IPv6 unrouted networks are not kept per /48")
	}

	ForgetSession(sess)
	if KnownUnrouted(sess, netip.MustParseAddr("216.235.193.1")) {
		t.Error("unrouted networks kept after the session ended")
	}
}
