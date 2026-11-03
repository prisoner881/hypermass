// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/netip"
	"strings"
	"sync"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

// IsReverseDNSName reports whether the name is in the reverse DNS tree
// (in-addr.arpa or ip6.arpa). Such a name only carries PTR records (and the
// CNAMEs of classless delegation, which a PTR lookup follows): a forward
// lookup on it (A, AAAA, CNAME, TXT) finds nothing.
func IsReverseDNSName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	return n == "in-addr.arpa" || n == "ip6.arpa" ||
		strings.HasSuffix(n, ".in-addr.arpa") || strings.HasSuffix(n, ".ip6.arpa")
}

// Broken reverse zones: networks whose reverse DNS does not answer.
//
// A reverse zone delegated to name servers that do not answer returns
// SERVFAIL for every name in it, and each PTR lookup is retried until it
// fails ("failed the maximum number of DNS attempts"). Once
// BrokenReverseZoneFailures lookups in a /24 (IPv6: /48) have failed with
// none answered, the session stops looking up its other addresses: an
// owned block filled address by address otherwise spent six attempts on
// every address of a zone that answers none. A lookup answered with "no
// such name" or "no PTR record" is an answer, and keeps the network open.
const BrokenReverseZoneFailures = 5

type reverseZone struct {
	mu       sync.Mutex
	failures int
	answered bool
}

// session ID + "|" + network -> *reverseZone
var reverseZones sync.Map

func reverseZoneFor(sess et.Session, addr netip.Addr) (*reverseZone, netip.Prefix, bool) {
	p, ok := unroutedNetwork(addr)
	if !ok || sess == nil {
		return nil, p, false
	}
	v, _ := reverseZones.LoadOrStore(sess.ID().String()+"|"+p.String(), &reverseZone{})
	return v.(*reverseZone), p, true
}

// RecordReverseLookup records the outcome of a PTR lookup for the address:
// failed when it failed every attempt, otherwise answered. It returns the
// address's network and whether this failure made the network's reverse
// zone count as broken.
func RecordReverseLookup(sess et.Session, addr netip.Addr, failed bool) (netip.Prefix, bool) {
	z, p, ok := reverseZoneFor(sess, addr)
	if !ok {
		return p, false
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if !failed {
		z.answered = true
		return p, false
	}
	z.failures++
	return p, !z.answered && z.failures == BrokenReverseZoneFailures
}

// ReverseZoneBroken reports whether PTR lookups in the address's network
// have failed BrokenReverseZoneFailures times this session with none
// answered.
func ReverseZoneBroken(sess et.Session, addr netip.Addr) bool {
	p, ok := unroutedNetwork(addr)
	if !ok || sess == nil {
		return false
	}
	v, found := reverseZones.Load(sess.ID().String() + "|" + p.String())
	if !found {
		return false
	}
	z := v.(*reverseZone)
	z.mu.Lock()
	defer z.mu.Unlock()
	return !z.answered && z.failures >= BrokenReverseZoneFailures
}
