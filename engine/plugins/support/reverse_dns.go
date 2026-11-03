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

// Broken forward zones: DNS zones whose name servers do not answer.
//
// A zone such as an Active Directory or wireless sub-zone that is delegated
// in public DNS but served only internally returns SERVFAIL for every name
// in it, and each lookup is retried until it fails. Names in such zones keep
// arriving (owned-block PTR records name hosts in them), and each was looked
// up four times (A/AAAA, CNAME, TXT, subdomains), six attempts each. Once
// lookups of BrokenForwardZoneNames distinct names in a zone have failed
// with none answered, the session stops forward lookups of the zone's other
// names. A lookup answered with "no such name" or "no record of this type"
// is an answer, and keeps the zone open.
//
// The zone of a name is the name without its first label. A registered
// domain (buffalo.edu) is never treated as broken, only zones below it
// (ad.med.buffalo.edu, wireless.buffalo.edu): a run of failures at the top
// of a target's domain is far more likely a resolver problem than a dead
// zone, and losing it would lose the enumeration.
const BrokenForwardZoneNames = 10

type forwardZone struct {
	mu       sync.Mutex
	failed   map[string]struct{}
	answered bool
}

// session ID + "|" + zone -> *forwardZone
var forwardZones sync.Map

// ForwardZone returns the zone of the name (the name without its first
// label), or "" when that zone is a registered domain or above it.
func ForwardZone(name string) string {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if IsReverseDNSName(n) {
		return ""
	}
	dom := RegisteredDomain(n)
	if dom == "" {
		return ""
	}
	i := strings.IndexByte(n, '.')
	if i < 0 {
		return ""
	}
	zone := n[i+1:]
	if len(zone) <= len(dom) || !strings.HasSuffix(zone, "."+dom) {
		return ""
	}
	return zone
}

// RecordForwardLookup records the outcome of a forward lookup of the name:
// failed when it failed every attempt, otherwise answered. It returns the
// name's zone and whether this failure made the zone count as broken.
func RecordForwardLookup(sess et.Session, name string, failed bool) (string, bool) {
	zone := ForwardZone(name)
	if zone == "" || sess == nil {
		return zone, false
	}
	v, _ := forwardZones.LoadOrStore(sess.ID().String()+"|"+zone, &forwardZone{failed: make(map[string]struct{})})
	z := v.(*forwardZone)
	z.mu.Lock()
	defer z.mu.Unlock()
	if !failed {
		z.answered = true
		return zone, false
	}
	if z.answered || len(z.failed) >= BrokenForwardZoneNames {
		return zone, false
	}
	z.failed[strings.ToLower(strings.TrimSuffix(name, "."))] = struct{}{}
	return zone, len(z.failed) == BrokenForwardZoneNames
}

// ForwardZoneBroken reports whether lookups of BrokenForwardZoneNames
// distinct names in the name's zone have failed this session with none
// answered.
func ForwardZoneBroken(sess et.Session, name string) bool {
	zone := ForwardZone(name)
	if zone == "" || sess == nil {
		return false
	}
	v, found := forwardZones.Load(sess.ID().String() + "|" + zone)
	if !found {
		return false
	}
	z := v.(*forwardZone)
	z.mu.Lock()
	defer z.mu.Unlock()
	return !z.answered && len(z.failed) >= BrokenForwardZoneNames
}
