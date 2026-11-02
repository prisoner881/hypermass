// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type netblock struct {
	name   string
	plugin *rdapPlugin
}

func (nb *netblock) Name() string {
	return nb.name
}

func (nb *netblock) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*network.Netblock)
	if !ok {
		return errors.New("failed to cast the Netblock asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Netblock), string(oam.IPNetRecord), nb.name)
	if err != nil {
		return err
	}

	var asset *dbt.Entity
	var record *rdap.IPNetwork
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, nb.plugin.source, since) {
		asset = nb.lookup(e, e.Entity, since)
	}
	// Queried again when the netblock has no registration record to show
	// for the lookup it is marked with: the record was never stored, or the
	// netblock was marked before records were stored under their registered
	// range.
	if asset == nil {
		var completed bool
		asset, record, completed = nb.query(e, e.Entity)
		if completed {
			support.MarkAssetMonitored(e.Session, e.Entity, nb.plugin.source)
		}
	}

	if asset != nil {
		// The record may already have been processed, with its contacts,
		// for another netblock it covers: the record of a /22 announced as
		// four /24s is processed once per session, when the first /24 is
		// linked to it. Check this netblock's ownership now that it is
		// linked, since its addresses may all have been checked before.
		support.AdmitOwnedNetblock(e, e.Entity)
		nb.process(e, record, asset)
	}
	return nil
}

// lookup returns the registration record that the netblock's last RDAP
// lookup linked to it. The record is found by the netblock's own
// "registration" edge, not by CIDR: a record is stored under the range it
// registers, which is often larger than the netblock (a /22 registration for
// an announced /24) and shared by several netblocks.
func (nb *netblock) lookup(e *et.Event, asset *dbt.Entity, since time.Time) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	edges, err := e.Session.DB().OutgoingEdges(ctx, asset, since, "registration")
	if err != nil {
		return nil
	}
	for _, edge := range edges {
		if edge.ToEntity == nil {
			continue
		}
		ipnet, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if err != nil || ipnet == nil {
			continue
		}
		if _, ok := ipnet.Asset.(*oamreg.IPNetRecord); !ok {
			continue
		}
		if tags, err := e.Session.DB().FindEntityTags(ctx, ipnet,
			since, nb.plugin.source.Name); err == nil && len(tags) > 0 {
			for _, tag := range tags {
				if tag.Property.PropertyType() == oam.SourceProperty {
					return ipnet
				}
			}
		}
	}
	return nil
}

// query also reports whether RDAP answered (see rdapLookupFailure); check()
// marks the netblock monitored only then.
func (nb *netblock) query(e *et.Event, asset *dbt.Entity) (*dbt.Entity, *rdap.IPNetwork, bool) {
	if err := nb.plugin.rlimit.Wait(e.Session.Ctx()); err != nil {
		return nil, nil, false
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Minute)
	defer cancel()

	n := asset.Asset.(*network.Netblock)
	_, ipnet, err := net.ParseCIDR(n.CIDR.String())
	if err != nil {
		return nil, nil, true
	}
	req := rdap.NewIPNetRequest(ipnet).WithContext(ctx)

	resp, err := nb.plugin.client.Do(req)
	if err != nil {
		reason := rdapLookupFailure(err)
		if reason != "" && e.Session.Ctx().Err() == nil {
			support.LogLookupFailure(nb.plugin.log, nb.plugin.name, n.CIDR.String(), reason)
		}
		return nil, nil, reason == ""
	}

	record, ok := resp.Object.(*rdap.IPNetwork)
	if !ok {
		return nil, nil, true
	}
	// RDAP answered, but an answer that could not be stored does not count
	// as a lookup: the netblock is queried again next time
	rec := nb.store(e, record, asset)
	return rec, record, rec != nil
}

// store saves the RDAP answer as an IPNetRecord linked to the netblock by a
// "registration" edge, and returns the record. The record is stored under
// the CIDR that the answer registers (registeredPrefix), which the database
// requires to contain the answer's start and end addresses. A failure is
// logged and nil returned.
func (nb *netblock) store(e *et.Event, resp *rdap.IPNetwork, asset *dbt.Entity) *dbt.Entity {
	n := asset.Asset.(*network.Netblock)

	start, err1 := netip.ParseAddr(resp.StartAddress)
	end, err2 := netip.ParseAddr(resp.EndAddress)
	if err1 != nil || err2 != nil {
		nb.storeFailed(e, n, resp, "the answer has no valid address range")
		return nil
	}
	cidr, start, end, ok := registeredPrefix(n.CIDR, start, end)
	if !ok {
		nb.storeFailed(e, n, resp, "the answer's address range does not cover the netblock")
		return nil
	}
	if resp.Handle == "" {
		nb.storeFailed(e, n, resp, "the answer has no handle")
		return nil
	}
	name := resp.Name
	if name == "" {
		name = resp.Handle
	}
	ntype := "IPv4"
	if cidr.Addr().Is6() {
		ntype = "IPv6"
	}

	ipnetrec := &oamreg.IPNetRecord{
		CIDR:         cidr,
		Handle:       resp.Handle,
		StartAddress: start,
		EndAddress:   end,
		Type:         ntype,
		Name:         name,
		Method:       resp.Type,
		Country:      resp.Country,
		ParentHandle: resp.ParentHandle,
		WhoisServer:  resp.Port43,
		Status:       resp.Status,
	}

	var reg, last bool
	for _, event := range resp.Events {
		switch event.Action {
		case "registration":
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				ipnetrec.CreatedDate = support.TimeToJSONString(&t)
				reg = true
			}
		case "last changed":
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				ipnetrec.UpdatedDate = support.TimeToJSONString(&t)
				last = true
			}
		}
	}
	if !reg || !last {
		nb.storeFailed(e, n, resp, "the answer lacks a registration or last changed date")
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	record, err := e.Session.DB().CreateAsset(ctx, ipnetrec)
	if err != nil || record == nil {
		reason := "the database did not return the record"
		if err != nil {
			reason = err.Error()
		}
		nb.storeFailed(e, n, resp, reason)
		return nil
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, record, &general.SourceProperty{
		Source:     nb.plugin.source.Name,
		Confidence: nb.plugin.source.Confidence,
	})

	if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "registration"},
		FromEntity: asset,
		ToEntity:   record,
	}); err == nil && edge != nil {
		_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
			Source:     nb.plugin.source.Name,
			Confidence: nb.plugin.source.Confidence,
		})
	}
	return record
}

func (nb *netblock) storeFailed(e *et.Event, n *network.Netblock, resp *rdap.IPNetwork, reason string) {
	e.Session.Log().Info("RDAP registration record not stored", "cidr", n.CIDR.String(),
		"handle", resp.Handle, "range", resp.StartAddress+" - "+resp.EndAddress, "reason", reason,
		slog.Group("plugin", "name", nb.plugin.name, "handler", nb.name))
}

// registeredPrefix returns the CIDR to store the registration of the
// address range start-end under, which RDAP returned for the netblock
// block, and the range clamped to that CIDR.
//
// RDAP answers a query for a netblock with the most specific registration
// covering it, which is often larger than the announced prefix: a company's
// /22 announced as four /24s. The record is stored under the registered
// range, which the database requires to contain its start and end
// addresses, so the netblocks it covers share one record. A range that is
// not a single CIDR block (99.10.64.0 - 99.75.191.255) is stored under the
// largest CIDR block inside it that contains the netblock, with the range
// clamped to that block, however many blocks the range would split into. An
// answer inside the netblock (smaller than the query) is stored under the
// netblock.
func registeredPrefix(block netip.Prefix, start, end netip.Addr) (netip.Prefix, netip.Addr, netip.Addr, bool) {
	block = block.Masked()
	if !block.IsValid() || !start.IsValid() || !end.IsValid() ||
		start.Is4() != block.Addr().Is4() || end.Is4() != block.Addr().Is4() {
		return netip.Prefix{}, start, end, false
	}

	// the largest CIDR block inside the range that contains the netblock
	for bits := 0; bits <= block.Bits(); bits++ {
		p, err := block.Addr().Prefix(bits)
		if err != nil {
			continue
		}
		first, last := p.Addr(), support.LastAddr(p)
		if first.Less(start) || end.Less(last) {
			continue
		}
		if first == start && last == end {
			return p, start, end, true
		}
		return p, first, last, true
	}
	if block.Contains(start) && block.Contains(end) {
		return block, start, end, true
	}
	return netip.Prefix{}, start, end, false
}

func (nb *netblock) process(e *et.Event, record *rdap.IPNetwork, asset *dbt.Entity) {
	ipnet := asset.Asset.(*oamreg.IPNetRecord)

	name := "IPNetRecord: " + ipnet.Handle
	_ = e.Dispatcher.DispatchEvent((&et.Event{
		Name:    name,
		Meta:    record,
		Entity:  asset,
		Session: e.Session,
	}))

	e.Session.Log().Info("relationship discovered", "from", ipnet.CIDR.String(), "relation",
		"registration", "to", name, slog.Group("plugin", "name", nb.plugin.name, "handler", nb.name))
}
