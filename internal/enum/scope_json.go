// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// ScopeJSONMarker starts the one stdout line that -scope-json writes. The
// rest of the line is a ScopeReport as JSON. A wrapper script reading enum's
// stdout picks this line out and passes every other line through.
const ScopeJSONMarker = "HYPERMASS_SCOPE "

// scopeFetchTimeout bounds each per-type scope request. A large session can
// hold tens of thousands of in-scope IP addresses.
const scopeFetchTimeout = 30 * time.Second

// ScopeReport is the session scope at the end of an enumeration: what the
// session treated as in scope (the seeds plus everything associated with them
// during the run), not the enumeration's findings. It exists only in the
// engine's memory and is gone once the session ends, so -scope-json captures
// it just before enum ends the session.
type ScopeReport struct {
	Session           string   `json:"session"`
	FQDNs             []string `json:"fqdn"`
	Netblocks         []string `json:"netblock"`
	AutonomousSystems []int    `json:"autonomoussystem"`
	IPAddresses       []string `json:"ipaddress"`
	// Errors maps an asset type to why its scope could not be read. A type
	// with an error has an empty list that means "unknown", not "none".
	Errors map[string]string `json:"errors,omitempty"`
}

type scopeFetcher func(ctx context.Context, atype oam.AssetType) ([]oam.Asset, error)

// buildScopeReport reads the session scope for the domain, netblock, ASN and
// IP address types, each list sorted. The engine answers 404 "session scope
// not found" for a type with nothing in scope; that is an empty list, not an
// error.
func buildScopeReport(token uuid.UUID, fetch scopeFetcher) *ScopeReport {
	rep := &ScopeReport{
		Session:           token.String(),
		FQDNs:             []string{},
		Netblocks:         []string{},
		AutonomousSystems: []int{},
		IPAddresses:       []string{},
	}

	for _, atype := range []oam.AssetType{oam.FQDN, oam.Netblock, oam.AutonomousSystem, oam.IPAddress} {
		ctx, cancel := context.WithTimeout(context.Background(), scopeFetchTimeout)
		assets, err := fetch(ctx, atype)
		cancel()
		if err != nil {
			if !strings.Contains(err.Error(), "session scope not found") {
				if rep.Errors == nil {
					rep.Errors = make(map[string]string)
				}
				rep.Errors[strings.ToLower(string(atype))] = err.Error()
			}
			continue
		}

		for _, a := range assets {
			switch v := a.(type) {
			case *oamdns.FQDN:
				rep.FQDNs = append(rep.FQDNs, v.Name)
			case *oamnet.Netblock:
				rep.Netblocks = append(rep.Netblocks, v.CIDR.String())
			case *oamnet.AutonomousSystem:
				rep.AutonomousSystems = append(rep.AutonomousSystems, v.Number)
			case *oamnet.IPAddress:
				rep.IPAddresses = append(rep.IPAddresses, v.Address.String())
			}
		}
	}

	sort.Strings(rep.FQDNs)
	sort.Slice(rep.Netblocks, func(i, j int) bool { return prefixLess(rep.Netblocks[i], rep.Netblocks[j]) })
	sort.Ints(rep.AutonomousSystems)
	sort.Slice(rep.IPAddresses, func(i, j int) bool { return addrLess(rep.IPAddresses[i], rep.IPAddresses[j]) })
	return rep
}

// prefixLess orders CIDRs by address, then prefix length; unparsable values
// sort after valid ones, as text.
func prefixLess(a, b string) bool {
	pa, erra := netip.ParsePrefix(a)
	pb, errb := netip.ParsePrefix(b)
	switch {
	case erra != nil && errb != nil:
		return a < b
	case erra != nil:
		return false
	case errb != nil:
		return true
	}
	if c := pa.Addr().Compare(pb.Addr()); c != 0 {
		return c < 0
	}
	return pa.Bits() < pb.Bits()
}

// addrLess orders IP addresses numerically (IPv4 before IPv6); unparsable
// values sort after valid ones, as text.
func addrLess(a, b string) bool {
	aa, erra := netip.ParseAddr(a)
	ab, errb := netip.ParseAddr(b)
	switch {
	case erra != nil && errb != nil:
		return a < b
	case erra != nil:
		return false
	case errb != nil:
		return true
	}
	return aa.Compare(ab) < 0
}

// writeScopeJSON writes the report as one marked line.
func writeScopeJSON(w io.Writer, rep *ScopeReport) error {
	raw, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s%s\n", ScopeJSONMarker, raw)
	return err
}

// printScopeJSON writes the session scope to w for -scope-json. It must run
// before the session is terminated.
func printScopeJSON(w io.Writer, c *client.Client, token uuid.UUID) error {
	return writeScopeJSON(w, buildScopeReport(token, func(ctx context.Context, atype oam.AssetType) ([]oam.Asset, error) {
		return c.SessionScope(ctx, token, atype)
	}))
}
