// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/netip"
	"sync"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

// Unrouted networks: addresses that BGP.Tools reports no BGP route for.
//
// A route more specific than a /24 (IPv4) or /48 (IPv6) is not carried on
// the global Internet, so when no route covers one address, none covers any
// other address in its /24 or /48 either. Recording the network lets the
// handlers that look up an address's BGP prefix skip the rest of it: an
// owned block filled address by address (a /20 of which only parts are
// announced) otherwise sent every unrouted address to BGP.Tools, one query
// per second, and kept IP-Netblock waiting 30 seconds on each for a prefix
// that never comes.

// session ID + "|" + network
var unroutedNetworks sync.Map

func unroutedNetwork(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	bits := 24
	if addr.Is6() {
		bits = 48
	}
	p, err := addr.Prefix(bits)
	return p, err == nil
}

// RecordUnrouted records that no BGP route covers the address, and returns
// the network recorded (its /24 or /48) and whether it is newly recorded in
// this session.
func RecordUnrouted(sess et.Session, addr netip.Addr) (netip.Prefix, bool) {
	p, ok := unroutedNetwork(addr)
	if !ok || sess == nil {
		return p, false
	}
	_, loaded := unroutedNetworks.LoadOrStore(sess.ID().String()+"|"+p.String(), struct{}{})
	return p, !loaded
}

// KnownUnrouted reports whether the address is in a network found to have
// no BGP route this session.
func KnownUnrouted(sess et.Session, addr netip.Addr) bool {
	p, ok := unroutedNetwork(addr)
	if !ok || sess == nil {
		return false
	}
	_, found := unroutedNetworks.Load(sess.ID().String() + "|" + p.String())
	return found
}
