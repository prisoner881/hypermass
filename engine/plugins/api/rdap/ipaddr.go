// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
)

// maxRDAPRangePrefixes bounds how many CIDR blocks an RDAP address range may
// split into before it is ignored.
const maxRDAPRangePrefixes = 8

// ipaddr looks up the most specific registration for each network the
// target's own IPs land in. The netblock handler queries RDAP with each
// IP's BGP prefix, which for an Internet provider's aggregate returns the
// provider's record; a smaller block reassigned to the target inside it
// ("Customer: Target Inc") is only returned by a query for an address in
// it. When the answer is more specific than the BGP prefix, it is stored as
// a netblock with its own registration record, and the usual ownership
// check (AdmitOwnedNetblock) decides whether it is the target's.
type ipaddr struct {
	name   string
	plugin *rdapPlugin
}

func (r *ipaddr) Name() string {
	return r.name
}

func (r *ipaddr) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*network.IPAddress)
	if !ok {
		return errors.New("failed to cast the IPAddress asset")
	}
	if !ip.Address.IsValid() || support.IsNonRoutableAddress(ip.Address) {
		return nil
	}

	// already covered: by an answer this session, or inside a netblock in scope
	if support.RDAPRangeKnown(e.Session, ip.Address) {
		return nil
	}
	if match, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf > 0 {
		if _, nb := match.(*network.Netblock); nb {
			return nil
		}
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	// only the target's own IPs: an in-scope name resolves to the address
	if !support.HasInScopeFQDN(ctx, e.Session, e.Entity) {
		return nil
	}

	r.query(e, ip)
	return nil
}

func (r *ipaddr) query(e *et.Event, ip *network.IPAddress) {
	addr := ip.Address
	// mark the address first, so a failed query is not repeated this session
	support.RecordRDAPRange(e.Session, netip.PrefixFrom(addr, addr.BitLen()))

	if err := r.plugin.rlimit.Wait(e.Session.Ctx()); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Minute)
	defer cancel()

	resp, err := r.plugin.client.Do(rdap.NewIPRequest(net.IP(addr.AsSlice())).WithContext(ctx))
	if err != nil {
		if reason := rdapLookupFailure(err); reason != "" && e.Session.Ctx().Err() == nil {
			support.LogLookupFailure(r.plugin.log, r.plugin.name, addr.String(), reason)
		}
		return
	}
	record, ok := resp.Object.(*rdap.IPNetwork)
	if !ok || record == nil {
		return
	}

	start, err1 := netip.ParseAddr(record.StartAddress)
	end, err2 := netip.ParseAddr(record.EndAddress)
	if err1 != nil || err2 != nil {
		return
	}
	prefixes := support.RangeToPrefixes(start, end, maxRDAPRangePrefixes)
	if len(prefixes) == 0 {
		return
	}
	support.RecordRDAPRange(e.Session, prefixes...)

	for _, p := range r.moreSpecific(e.Session, addr, prefixes) {
		r.store(e, p, ip, record)
	}
}

// moreSpecific returns the blocks of the RDAP answer that are smaller than
// the address's BGP prefix and inside it: the netblock handler already has
// the registration for the prefix itself. Without a BGP prefix to compare
// with, only blocks no larger than a /16 (IPv4) or /32 (IPv6) are kept.
func (r *ipaddr) moreSpecific(sess et.Session, addr netip.Addr, prefixes []netip.Prefix) []netip.Prefix {
	var bgp netip.Prefix
	if entry := support.IPNetblock(sess, addr.String()); entry != nil && entry.Net != nil {
		if p, err := netip.ParsePrefix(entry.Net.String()); err == nil {
			bgp = p.Masked()
		}
	}

	var results []netip.Prefix
	for _, p := range prefixes {
		if bgp.IsValid() {
			if p.Bits() > bgp.Bits() && bgp.Contains(p.Addr()) {
				results = append(results, p)
			}
			continue
		}
		if (p.Addr().Is4() && p.Bits() >= 16) || (p.Addr().Is6() && p.Bits() >= 32) {
			results = append(results, p)
		}
	}
	return results
}

// store saves the block as a netblock with the RDAP answer as its
// registration record, and hands the record to the IPNetRecord handler,
// which stores its contacts and runs the ownership check.
func (r *ipaddr) store(e *et.Event, p netip.Prefix, ip *network.IPAddress, record *rdap.IPNetwork) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	ntype := "IPv4"
	if p.Addr().Is6() {
		ntype = "IPv6"
	}
	nb, err := e.Session.DB().CreateAsset(ctx, &network.Netblock{CIDR: p, Type: ntype})
	if err != nil || nb == nil {
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, nb, &general.SourceProperty{
		Source:     r.plugin.source.Name,
		Confidence: r.plugin.source.Confidence,
	})

	if p.Contains(ip.Address) {
		if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "contains"},
			FromEntity: nb,
			ToEntity:   e.Entity,
		}); err == nil && edge != nil {
			_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
				Source:     r.plugin.source.Name,
				Confidence: r.plugin.source.Confidence,
			})
		}
	}

	// the netblock handler need not query RDAP again for this block
	support.MarkAssetMonitored(e.Session, nb, r.plugin.source)

	if rec := r.plugin.netblock.store(e, record, nb); rec != nil {
		r.plugin.netblock.process(e, record, rec)
	}
}
