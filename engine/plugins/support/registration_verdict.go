// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/net/publicsuffix"
)

// Verdict is what a registration record says about who owns an asset.
type Verdict int

const (
	// VerdictNoInfo: the record names no one usable (no contacts, only
	// placeholders, only freemail).
	VerdictNoInfo Verdict = iota
	// VerdictOwner: the record names the target.
	VerdictOwner
	// VerdictForeign: the record names a different, real organization.
	VerdictForeign
)

func (v Verdict) String() string {
	switch v {
	case VerdictOwner:
		return "owner"
	case VerdictForeign:
		return "foreign"
	default:
		return "no information"
	}
}

// RegistrationEvidence is what the verdict was based on, for logging.
type RegistrationEvidence struct {
	Registrants  []string // registrant organization names
	EmailDomains []string // contact email domains
}

// RegistrationVerdict judges an IPNetRecord or AutnumRecord by its RDAP
// contacts.
//
//   - Owner: a contact email on a seed domain, or a registrant organization
//     that is in scope.
//   - Foreign: a registrant organization that is a real name (not a role,
//     placeholder or care-of text) and not in scope, together with at least
//     one contact email on a non-freemail domain that is not in scope. The
//     record then belongs to that organization: a provider, an Internet
//     provider, a managed-service provider.
//   - No information otherwise.
//
// The record is live RDAP data, so the verdict needs no history in the
// database.
func RegistrationVerdict(ctx context.Context, sess et.Session, rec *dbt.Entity) (Verdict, RegistrationEvidence) {
	var ev RegistrationEvidence
	if sess == nil || rec == nil {
		return VerdictNoInfo, ev
	}
	switch rec.Asset.(type) {
	case *oamreg.IPNetRecord, *oamreg.AutnumRecord:
	default:
		return VerdictNoInfo, ev
	}

	edges, err := sess.DB().OutgoingEdges(ctx, rec, time.Time{},
		"registrant", "admin_contact", "abuse_contact", "technical_contact")
	if err != nil {
		return VerdictNoInfo, ev
	}

	var realRegistrant, registrantInScope, seedEmail, foreignEmail bool
	names := map[string]struct{}{}
	domains := map[string]struct{}{}
	for _, edge := range edges {
		if edge.ToEntity == nil {
			continue
		}
		registrant := edge.Relation != nil && edge.Relation.Label() == "registrant"

		if registrant {
			for _, o := range contactOrganizations(ctx, sess, edge.ToEntity) {
				if IsGenericName(o.Name) || IsCareOfOrMailDrop(o.Name) {
					continue
				}
				names[o.Name] = struct{}{}
				realRegistrant = true
				if orgInScope(sess, o) {
					registrantInScope = true
				}
			}
		}

		for _, email := range contactEmails(ctx, sess, edge.ToEntity) {
			dom := emailDomain(email)
			if dom == "" {
				continue
			}
			domains[dom] = struct{}{}
			if sess.Config().IsDomainInScope(dom) {
				seedEmail = true
				continue
			}
			if IsFreemailDomain(dom) {
				continue
			}
			if _, conf := sess.Scope().IsAssetInScope(&oamdns.FQDN{Name: dom}, 0); conf > 0 {
				continue
			}
			foreignEmail = true
		}
	}

	ev.Registrants = sortedKeys(names)
	ev.EmailDomains = sortedKeys(domains)
	switch {
	case seedEmail || registrantInScope:
		return VerdictOwner, ev
	case realRegistrant && foreignEmail:
		return VerdictForeign, ev
	default:
		return VerdictNoInfo, ev
	}
}

// orgInScope reports whether the organization is in scope by exact name.
// A confidence of 100 keeps the scope's fuzzy name matching out of it.
func orgInScope(sess et.Session, o *oamorg.Organization) bool {
	_, conf := sess.Scope().IsAssetInScope(o, 100)
	return conf >= 100
}

func contactOrganizations(ctx context.Context, sess et.Session, cr *dbt.Entity) []*oamorg.Organization {
	var results []*oamorg.Organization
	if edges, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "organization"); err == nil {
		for _, edge := range edges {
			if edge.ToEntity == nil {
				continue
			}
			if ent, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && ent != nil {
				if o, ok := ent.Asset.(*oamorg.Organization); ok {
					results = append(results, o)
				}
			}
		}
	}
	return results
}

func contactEmails(ctx context.Context, sess et.Session, cr *dbt.Entity) []string {
	var results []string
	if edges, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if edge.ToEntity == nil {
				continue
			}
			if ent, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && ent != nil {
				if id, ok := ent.Asset.(*general.Identifier); ok && id.Type == general.EmailAddress {
					results = append(results, id.ID)
				}
			}
		}
	}
	return results
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// DeclineForeignRegistration logs and reports whether the registration
// record (IPNetRecord or AutnumRecord) is foreign and the caller must not
// admit what it registers. Assets the operator seeded are never declined.
func DeclineForeignRegistration(sess et.Session, rec *dbt.Entity, plugin string) bool {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 15*time.Second)
	defer cancel()

	v, ev := RegistrationVerdict(ctx, sess, rec)
	if v != VerdictForeign {
		return false
	}

	atype, key := string(rec.Asset.AssetType()), rec.Asset.Key()
	switch r := rec.Asset.(type) {
	case *oamreg.IPNetRecord:
		key = r.CIDR.String()
	case *oamreg.AutnumRecord:
		key = "AS" + strings.TrimPrefix(r.Handle, "AS")
	}
	return Decline(sess, VetoForeignRegistrant, atype, key, plugin,
		"registrant", strings.Join(ev.Registrants, "; "), "email_domains", strings.Join(ev.EmailDomains, ", "))
}

// Per-IP RDAP: the netblocks already answered for in a session, so each
// network the target's IPs land in is queried once.

type rdapRangeSet struct {
	mu       sync.Mutex
	prefixes []netip.Prefix
}

var rdapRanges sync.Map // session ID -> *rdapRangeSet

func rdapRangeSetFor(sess et.Session) *rdapRangeSet {
	v, _ := rdapRanges.LoadOrStore(sess.ID().String(), &rdapRangeSet{})
	return v.(*rdapRangeSet)
}

// RDAPRangeKnown reports whether an RDAP answer this session already covers
// the IP address.
func RDAPRangeKnown(sess et.Session, ip netip.Addr) bool {
	rs := rdapRangeSetFor(sess)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, p := range rs.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// RecordRDAPRange records netblocks covered by an RDAP answer this session.
func RecordRDAPRange(sess et.Session, prefixes ...netip.Prefix) {
	rs := rdapRangeSetFor(sess)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.prefixes = append(rs.prefixes, prefixes...)
}

func forgetRDAPRanges(sess et.Session) {
	rdapRanges.Delete(sess.ID().String())
}

// RangeToPrefixes returns the CIDR blocks that exactly cover the address
// range start-end (inclusive), at most max of them; nil if the range is
// invalid or needs more blocks than that.
func RangeToPrefixes(start, end netip.Addr, max int) []netip.Prefix {
	if !start.IsValid() || !end.IsValid() || start.Is4() != end.Is4() || end.Less(start) {
		return nil
	}
	var out []netip.Prefix
	for cur := start; ; {
		bits := cur.BitLen()
		// the largest block starting at cur that does not pass end
		for bits > 0 {
			p, err := cur.Prefix(bits - 1)
			if err != nil || p.Addr() != cur || lastAddr(p).Compare(end) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(cur, bits)
		out = append(out, p)
		if len(out) > max {
			return nil
		}
		last := lastAddr(p)
		if last.Compare(end) >= 0 {
			return out
		}
		cur = last.Next()
		if !cur.IsValid() {
			return out
		}
	}
}

// LastAddr returns the last address in the prefix.
func LastAddr(p netip.Prefix) netip.Addr {
	return lastAddr(p)
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	bits := p.Bits()
	for i := range a {
		for b := 0; b < 8; b++ {
			if i*8+b >= bits {
				a[i] |= 1 << (7 - b)
			}
		}
	}
	addr, _ := netip.AddrFromSlice(a)
	return addr
}

// RegisteredDomain returns the registered domain (eTLD+1) of a host name.
func RegisteredDomain(name string) string {
	name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
	dom, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return dom
}
