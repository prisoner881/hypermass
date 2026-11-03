// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// Scope decisions. A veto is a reason, found in the data, why an asset that
// would be added to the session scope belongs to someone else. Every veto
// is logged as "scope decision"; whether it blocks depends on the session's
// scope_vetoes setting (config.ScopeVetoMode).

// Veto reasons, as logged.
const (
	VetoResolutionOnly    = "resolution only: an in-scope name resolving into a netblock does not make it the target's"
	VetoForeignRegistrant = "registration names another organization"
	VetoMergedCertificate = "merged certificate: unrelated certificates share this serial number"
	VetoSharedASN         = "shared infrastructure: the ASN announces too many netblocks"
)

// session ID + reason + asset, so each decision is logged once per session.
var decisionsLogged sync.Map

// Decline records a veto on adding the asset to scope and reports whether
// the caller must block the addition: true in enforce mode, false in
// observe mode (logged as "would decline") and off mode (not logged).
func Decline(sess et.Session, reason, atype, asset, plugin string, kv ...any) bool {
	mode := sess.Config().ScopeVetoMode()
	if mode == config.ScopeVetoesOff {
		return false
	}

	key := sess.ID().String() + "|" + reason + "|" + atype + "|" + asset
	if _, logged := decisionsLogged.LoadOrStore(key, struct{}{}); !logged {
		action := "declined"
		if mode == config.ScopeVetoesObserve {
			action = "would decline"
		}
		args := append([]any{"action", action, "reason", reason, "type", atype, "asset", asset}, kv...)
		args = append(args, slog.Group("plugin", "name", plugin))
		sess.Log().Info("scope decision", args...)
	}
	return mode == config.ScopeVetoesEnforce
}

// Provenance: how far each scope addition is from the seeds, counted in
// admissions (a seed is 0, an asset admitted because of a seed is 1, and so
// on). Recorded and logged now; later phases limit how far weak evidence
// may carry scope.

// session ID + asset type + key -> distance
var scopeDistances sync.Map

func distanceKey(sess et.Session, a oam.Asset) string {
	a = canonicalScopeAsset(a)
	key := a.Key()
	// scope matches an organization by name, and many Organization entities
	// carry the same name, so its distance is kept by name too
	if o, ok := a.(*oamorg.Organization); ok {
		if key = strings.TrimSpace(o.Name); key == "" {
			key = strings.TrimSpace(o.LegalName)
		}
	}
	return sess.ID().String() + "|" + string(a.AssetType()) + "|" + strings.ToLower(key)
}

// canonicalScopeAsset maps a registration record to the asset it registers,
// which is what is in scope: a DomainRecord to its domain, an IPNetRecord to
// its netblock, an AutnumRecord to its autonomous system.
func canonicalScopeAsset(a oam.Asset) oam.Asset {
	switch v := a.(type) {
	case *oamreg.DomainRecord:
		return &oamdns.FQDN{Name: v.Domain}
	case *oamreg.IPNetRecord:
		return &oamnet.Netblock{CIDR: v.CIDR, Type: v.Type}
	case *oamreg.AutnumRecord:
		return &oamnet.AutonomousSystem{Number: v.Number}
	}
	return a
}

// IsSeedAsset reports whether the asset is one the operator put in scope:
// a seed domain (or a name under one), seed address, CIDR or ASN.
func IsSeedAsset(sess et.Session, a oam.Asset) bool {
	cfg := sess.Config()
	if cfg == nil || cfg.Scope == nil {
		return false
	}
	switch v := a.(type) {
	case *oamdns.FQDN:
		return cfg.IsDomainInScope(v.Name)
	case *oamreg.DomainRecord:
		return cfg.IsDomainInScope(v.Domain)
	case *oamnet.IPAddress:
		return cfg.IsAddressInScope(v.Address.String())
	case *oamnet.Netblock:
		for _, c := range cfg.Scope.CIDRs {
			if c == nil {
				continue
			}
			if ones, _ := c.Mask.Size(); c.Contains(net.IP(v.CIDR.Addr().AsSlice())) && ones <= v.CIDR.Bits() {
				return true
			}
		}
	case *oamnet.AutonomousSystem:
		for _, asn := range cfg.Scope.ASNs {
			if asn == v.Number {
				return true
			}
		}
	}
	return false
}

// ScopeDistance is the asset's distance from the seeds: 0 for a seed, the
// recorded distance for an asset admitted this session, -1 when unknown.
func ScopeDistance(sess et.Session, a oam.Asset) int {
	if a == nil {
		return -1
	}
	if IsSeedAsset(sess, canonicalScopeAsset(a)) {
		return 0
	}
	if v, ok := scopeDistances.Load(distanceKey(sess, a)); ok {
		return v.(int)
	}
	return -1
}

// RecordScopeAddition records that the asset joined scope because of from
// (nil when unknown) and returns its distance from the seeds (-1 when
// unknown). The shortest distance seen is kept.
func RecordScopeAddition(sess et.Session, a, from oam.Asset) int {
	if a == nil {
		return -1
	}
	if IsSeedAsset(sess, canonicalScopeAsset(a)) {
		return 0
	}
	d := -1
	if from != nil {
		if pd := ScopeDistance(sess, from); pd >= 0 {
			d = pd + 1
		}
	}
	if d < 0 {
		return -1
	}
	key := distanceKey(sess, a)
	for {
		v, loaded := scopeDistances.LoadOrStore(key, d)
		if !loaded {
			return d
		}
		if old := v.(int); old <= d {
			return old
		} else if scopeDistances.CompareAndSwap(key, old, d) {
			return d
		}
	}
}

// freemailDomains are mail services anyone can use. A contact email there
// says nothing about which organization the contact belongs to.
var freemailDomains = map[string]struct{}{}

func init() {
	for _, d := range []string{
		"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
		"yahoo.com", "ymail.com", "rocketmail.com", "aol.com", "icloud.com", "me.com", "mac.com",
		"proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "gmx.de", "web.de",
		"mail.com", "mail.ru", "inbox.ru", "list.ru", "bk.ru", "yandex.ru", "yandex.com", "ya.ru",
		"qq.com", "163.com", "126.com", "sina.com", "sohu.com", "naver.com", "hanmail.net",
		"zoho.com", "zohomail.com", "tutanota.com", "fastmail.com", "hey.com", "rediffmail.com",
		"libero.it", "orange.fr", "laposte.net", "free.fr", "t-online.de", "seznam.cz", "wp.pl",
		"o2.pl", "interia.pl", "yahoo.co.uk", "yahoo.co.jp", "yahoo.fr", "yahoo.de",
	} {
		freemailDomains[d] = struct{}{}
	}
}

// IsFreemailDomain reports whether the mail domain is a public mail service.
func IsFreemailDomain(domain string) bool {
	_, ok := freemailDomains[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))]
	return ok
}

// entityCacheKey identifies an entity across sessions for the
// process-wide verdict caches: entity IDs are unique only within one
// database, and the engine API lets each session use its own. The primary
// database is identified by its system, host, port and name (no
// credentials).
func entityCacheKey(sess et.Session, id string) string {
	cfg := sess.Config()
	if cfg == nil || len(cfg.GraphDBs) == 0 {
		return "|" + id
	}
	db := cfg.GraphDBs[0]
	for _, d := range cfg.GraphDBs {
		if d != nil && d.Primary {
			db = d
			break
		}
	}
	if db == nil {
		return "|" + id
	}
	return strings.ToLower(db.System+"|"+db.Host+"|"+db.Port+"|"+db.DBName) + "|" + id
}

// ForgetSession drops the per-session state kept by the scope decision
// helpers once a session has ended.
func ForgetSession(sess et.Session) {
	if sess == nil {
		return
	}
	prefix := sess.ID().String() + "|"
	for _, m := range []*sync.Map{
		&decisionsLogged, &scopeDistances, &sharedLocationsLogged, &roleOrgsLogged, &ownedAdmitted, &unroutedNetworks,
	} {
		m.Range(func(k, _ any) bool {
			if s, ok := k.(string); ok && strings.HasPrefix(s, prefix) {
				m.Delete(k)
			}
			return true
		})
	}
	forgetRDAPRanges(sess)
}
