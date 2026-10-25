// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"net/netip"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
)

// An ASN that announces more than the cap is treated as shared infrastructure
// (a CDN, cloud or SaaS provider), and its announced space is not admitted to
// scope. A target that runs its own ASN announces far fewer blocks.
func TestIsSharedInfrastructureASN(t *testing.T) {
	cases := []struct {
		announced int
		shared    bool
	}{
		{0, false},
		{3, false},
		{maxAnnouncedNetblocksForScope, false},
		{maxAnnouncedNetblocksForScope + 1, true},
		{500, true}, // a provider such as Cloudflare announces hundreds
	}
	for _, c := range cases {
		if got := isSharedInfrastructureASN(c.announced); got != c.shared {
			t.Errorf("isSharedInfrastructureASN(%d) = %v, want %v", c.announced, got, c.shared)
		}
	}
}

// For an ASN that is not shared infrastructure, the fan-out admits only the
// same small IPv4 blocks the ambient netblock path admits; large blocks and
// IPv6 are left to the ownership path, so a single over-associated ASN cannot
// pull a provider-sized block in on this associative signal.
func TestAnnouncedNetblockSizeGate(t *testing.T) {
	cases := []struct {
		cidr string
		want bool
	}{
		{"198.51.100.0/24", true},
		{"203.0.113.0/20", true},
		{"104.16.0.0/12", false},  // provider-sized block, too large for this signal
		{"10.0.0.0/8", false},     // far too large
		{"2606:4700::/44", false}, // IPv6 is never admitted on this path
	}
	for _, c := range cases {
		if got := support.PrefixEligibleForAmbientAdmit(netip.MustParsePrefix(c.cidr)); got != c.want {
			t.Errorf("PrefixEligibleForAmbientAdmit(%s) = %v, want %v", c.cidr, got, c.want)
		}
	}
}
