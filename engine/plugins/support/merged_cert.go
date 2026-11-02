// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// The asset database keeps one TLS certificate per serial number. Serials
// are unique only per issuer, and default and self-signed certificates on
// appliances reuse a few (0, 1, ...), so every such certificate in the world
// becomes one stored certificate whose common names, subject contacts and
// organizations belong to unrelated parties: one stored "certificate" with
// serial 1 linked 84 organizations. A genuine certificate has one common
// name and one subject organization. A merged one says nothing about
// ownership and must not carry scope.

var mergedCerts sync.Map // database + certificate entity ID -> struct{}, merged ones only

// IsMergedCertificate reports whether the stored certificate merges
// unrelated certificates: its common names fall under more than one
// registered domain, or its subject contacts name more than one real
// organization. Merged verdicts are cached: a merged record only ever gains
// more links.
func IsMergedCertificate(ctx context.Context, sess et.Session, cert *dbt.Entity) bool {
	if sess == nil || cert == nil {
		return false
	}
	if _, ok := cert.Asset.(*oamcert.TLSCertificate); !ok {
		return false
	}
	if _, ok := mergedCerts.Load(entityCacheKey(sess, cert.ID)); ok {
		return true
	}

	merged := func() bool {
		domains := map[string]struct{}{}
		if edges, err := sess.DB().OutgoingEdges(ctx, cert, time.Time{}, "common_name"); err == nil {
			for _, edge := range edges {
				if edge.ToEntity == nil {
					continue
				}
				ent, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID)
				if err != nil || ent == nil {
					continue
				}
				if f, ok := ent.Asset.(*oamdns.FQDN); ok {
					if dom := RegisteredDomain(f.Name); dom != "" {
						domains[dom] = struct{}{}
						if len(domains) > 1 {
							return true
						}
					}
				}
			}
		}

		orgs := map[string]struct{}{}
		if edges, err := sess.DB().OutgoingEdges(ctx, cert, time.Time{}, "subject_contact"); err == nil {
			for _, edge := range edges {
				if edge.ToEntity == nil {
					continue
				}
				for _, o := range contactOrganizations(ctx, sess, edge.ToEntity) {
					if IsGenericName(o.Name) {
						continue
					}
					orgs[strings.Join(nameWords(o.Name), " ")] = struct{}{}
					if len(orgs) > 1 {
						return true
					}
				}
			}
		}
		return false
	}()

	if merged {
		mergedCerts.Store(entityCacheKey(sess, cert.ID), struct{}{})
	}
	return merged
}

// DeclineMergedCertificate logs and reports whether the certificate is a
// merged one that the caller must not use to expand scope.
func DeclineMergedCertificate(sess et.Session, cert *dbt.Entity, plugin string) bool {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 15*time.Second)
	defer cancel()

	if !IsMergedCertificate(ctx, sess, cert) {
		return false
	}
	c := cert.Asset.(*oamcert.TLSCertificate)
	return Decline(sess, VetoMergedCertificate, string(c.AssetType()), c.SerialNumber, plugin,
		"common_name", c.SubjectCommonName)
}

func init() {
	// Scope association runs in the scope package, which cannot import this
	// one; it asks here whether an asset may serve as evidence.
	scope.SkipAssociationEvidence = func(sess et.Session, ent *dbt.Entity) bool {
		if _, ok := ent.Asset.(*oamcert.TLSCertificate); ok {
			return DeclineMergedCertificate(sess, ent, "Scope-Association")
		}
		return false
	}
}
