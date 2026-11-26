// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

const (
	sweepIdlePoll    = 2 * time.Second
	sweepIdleTimeout = 2 * time.Minute
	sweepDrainWait   = 15 * time.Minute
	sweepMaxResubmit = 500
)

// SweepMissedIPs is the session-end catch-up for Protocol-Probes.
//
// It runs only against IPs that this session already processed
// (backlog state=done), that have open_port tags, that have no
// Protocol-Probes last_monitored mark inside the transform TTL, and
// that resolve from an FQDN under a configured domain or a domain added
// to the session scope during the run (see seedScopedIP). Those are the
// hosts that hit position 43 with an empty port list, or that were
// scanned only from the FQDN pipeline.
//
// Must be called while the session context and dispatcher pump are
// still alive — before Session.Kill().
func SweepMissedIPs(s et.Session, d et.Dispatcher) {
	if s == nil || d == nil || s.Backlog() == nil || s.Done() {
		return
	}
	if !s.Config().Active {
		return
	}

	log := s.Log().WithGroup("plugin").With("name", "Protocol-Probes").With("handler", "session-end-sweep")
	support.SetEndWorkPhase(s, "idle-wait")

	if !waitIPIdle(s, sweepIdleTimeout) {
		log.Warn("IP pipeline still busy; sweeping only Done rows")
	}

	support.SetEndWorkPhase(s, "listing")
	ids, err := s.Backlog().ListDone(oam.IPAddress)
	if err != nil {
		log.Error("failed to list Done IP backlog rows", "error", err.Error())
		return
	}

	prefilterSince, err := support.PrefilterTTLStartTime(s)
	if err != nil {
		log.Error("failed to compute prefilter TTL window", "error", err.Error())
		return
	}
	protoSince, err := support.TTLStartTime(s.Config(), string(oam.IPAddress), string(oam.Service), "Protocol-Probes")
	if err != nil {
		log.Error("failed to compute Protocol-Probes TTL window", "error", err.Error())
		return
	}

	src := &et.Source{Name: "Protocol-Probes", Confidence: 80}

	// misses come from the batched query, which has already applied the
	// filters; walk holds IPs that must be checked one at a time.
	var misses, walk []string
	res, batched, reason := missListBatch(s, log, ids, prefilterSince, protoSince)
	if batched {
		misses, walk = res.misses, res.walk
		log.Info("batch miss-list query",
			"done_ips", len(ids), "misses", len(misses),
			"failed_chunks", res.failedChunks, "walk_ips", len(walk),
			"slowest_chunk", res.slowest.Round(100*time.Millisecond).String())
	} else {
		walk = ids
		log.Warn("batched miss-list query not available; checking every Done IP one at a time",
			"reason", reason, "done_ips", len(ids))
	}
	support.SetEndWorkCandidates(s, len(misses)+len(walk))
	support.SetEndWorkPhase(s, "requeue")

	var submitted int
	capLogged := false
	// requeue submits ids, checking each against the walk's filters unless
	// skipFilters is set. It returns false when the session ended.
	requeue := func(ids []string, skipFilters bool) bool {
		for _, id := range ids {
			// The session was terminated while end-work was running: stop
			// requeueing instead of walking the rest of the Done list.
			if s.Done() {
				log.Info("session ended during sweep; stopping requeue")
				return false
			}
			if submitted >= sweepMaxResubmit {
				if !capLogged {
					log.Warn("sweep cap reached", "cap", sweepMaxResubmit)
					capLogged = true
				}
				return true
			}

			ctx, cancel := context.WithTimeout(s.Ctx(), 5*time.Second)
			ent, ferr := s.DB().FindEntityById(ctx, id)
			cancel()
			if ferr != nil || ent == nil {
				continue
			}
			if _, ok := ent.Asset.(*oamnet.IPAddress); !ok {
				continue
			}

			if !skipFilters {
				if !seedScopedIP(s, ent) {
					continue
				}
				ports := support.OpenPortsForIP(s.Ctx(), s, ent, prefilterSince)
				if len(ports) == 0 {
					continue
				}
				if support.AssetMonitoredWithinTTL(s, ent, src, protoSince) {
					continue
				}
			}

			ev := &et.Event{
				Name:       string(oam.IPAddress) + ": " + ent.Asset.Key(),
				Entity:     ent,
				Dispatcher: d,
				Session:    s,
			}

			var submitErr error
			if s.Backlog().Has(ent) {
				submitErr = d.ResubmitEvent(ev)
			} else {
				submitErr = d.DispatchEvent(ev)
			}
			if submitErr != nil {
				log.Warn("failed to requeue IP for Protocol-Probes",
					"ip", ent.Asset.Key(), "error", submitErr.Error())
				continue
			}
			submitted++
			support.AddEndWorkRequeued(s, 1)
			log.Info("requeued IP for Protocol-Probes", "ip", ent.Asset.Key())
		}
		return true
	}
	if !requeue(misses, true) || !requeue(walk, false) {
		return
	}

	if submitted == 0 {
		support.SetEndWorkPhase(s, "done")
		log.Info("session-end sweep found no missed IPs")
		return
	}

	log.Info("session-end sweep requeued IPs", "count", submitted)
	support.SetEndWorkPhase(s, "drain")
	if !waitIPIdle(s, sweepDrainWait) {
		log.Warn("timed out waiting for swept IPs to drain")
	}
	support.SetEndWorkPhase(s, "done")
}

// seedScopedIP reports whether a name under one of the session's scope
// domains resolves to ent. That is a configured domain (including a
// configured subdomain, which the session scope does not store because it
// keeps registered domains only) or a domain added to the session scope
// during the run, for example by horizontal expansion. Runtime additions
// only exist when -rigid is off, and every candidate must already carry a
// fresh open_port tag, so this never selects a host that was not already
// scanned in this session.
func seedScopedIP(s et.Session, ent *dbt.Entity) bool {
	ctx, cancel := context.WithTimeout(s.Ctx(), 5*time.Second)
	defer cancel()

	for _, fqdn := range support.ResolvingFQDNs(ctx, s, ent) {
		if s.Config().IsDomainInScope(fqdn.Name) {
			return true
		}
		if _, conf := s.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
			return true
		}
	}
	return false
}

// sweepSeedDomains returns the configured domains plus the domains in the
// session scope, lowercased and de-duplicated, for the batch miss-list
// query. It is the batch equivalent of seedScopedIP's two checks.
func sweepSeedDomains(s et.Session) []string {
	var all []string
	if cfg := s.Config(); cfg != nil {
		all = append(all, cfg.Domains()...)
	}
	if sc := s.Scope(); sc != nil {
		all = append(all, sc.Domains()...)
	}

	seen := make(map[string]struct{}, len(all))
	var domains []string
	for _, d := range all {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
	}
	return domains
}

func waitIPIdle(s et.Session, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.Done() {
			return false
		}
		q, l, _, err := s.Backlog().Counts(oam.IPAddress)
		if err == nil && q == 0 && l == 0 {
			return true
		}
		time.Sleep(sweepIdlePoll)
	}
	return false
}
