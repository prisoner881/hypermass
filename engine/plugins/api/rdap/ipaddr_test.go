// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"net"
	"net/netip"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/yl2chen/cidranger"
)

type rangerSession struct {
	et.Session
	ranger cidranger.Ranger
}

func (s *rangerSession) CIDRanger() cidranger.Ranger { return s.ranger }

// Only an RDAP answer more specific than the address's BGP prefix is new:
// the netblock handler already has the registration for the prefix itself.
func TestMoreSpecific(t *testing.T) {
	r := &ipaddr{}
	sess := &rangerSession{ranger: sessions.NewAmassRanger()}
	_, bgp, _ := net.ParseCIDR("203.0.0.0/16")
	if err := sess.ranger.Insert(&sessions.CIDRangerEntry{Net: bgp, ASN: 64500}); err != nil {
		t.Fatal(err)
	}

	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	addr := netip.MustParseAddr("203.0.113.10")

	// a /27 reassigned to the target inside the provider's /16
	if got := r.moreSpecific(sess, addr, pfx("203.0.113.0/27")); len(got) != 1 || got[0].String() != "203.0.113.0/27" {
		t.Errorf("reassignment inside the prefix: got %v", got)
	}
	// the prefix itself, and a block outside it
	if got := r.moreSpecific(sess, addr, pfx("203.0.0.0/16", "198.51.100.0/24")); len(got) != 0 {
		t.Errorf("same prefix or outside it: got %v, want none", got)
	}

	// no BGP prefix known for the address: keep only blocks no larger than a /16
	other := netip.MustParseAddr("192.0.2.10")
	if got := r.moreSpecific(sess, other, pfx("192.0.2.0/24", "192.0.0.0/12")); len(got) != 1 || got[0].String() != "192.0.2.0/24" {
		t.Errorf("no BGP prefix: got %v, want only 192.0.2.0/24", got)
	}
}
