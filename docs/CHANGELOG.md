# Hypermass Changelog

Every change from stock OWASP Amass v5.1.1 to Hypermass 1.2, newest
release first, with what changed and why. `docs/HYPERMASS_BRIEFING.md`
explains each feature as it works today (cited as "briefing §n");
`docs/MAINTAINERS.md` has the file-level detail and long incident
write-ups (cited as "MAINTAINERS n.n").

**How this was reconstructed.** The repository had no changelog until
this file. It is rebuilt from the Git history and the pull requests:
- **Upstream base:** `79299dce` ("updated to v5.1.1", 2026-04-06), the
  last upstream commit. `git diff 79299dce origin/hypermass-1.2` is the
  whole fork.
- **Pre-release (2026-08-21 → 09-21):** the first version was built
  through GitHub's web upload, so about 190 commits say only "Add files
  via upload" or "Update <file>". Those entries are reconstructed from the
  files each commit touched, the code and MAINTAINERS; dates are commit
  dates. Tag `sd-freeze-2026-09-10` marks the last known-good state.
- **From 2026-09-24:** named commits, then pull requests (#1 onward), each
  with a full commit message describing the problem and the fix.

| Release | Branch / tag | Dates | PRs |
|---|---|---|---|
| 1.2 | `hypermass-1.2` (active) | 2026-11-24 → | #33 → |
| 1.1 | `hypermass-1.1` (untagged) | 2026-10-15 → 11-05 | #11–#32 |
| 1.0 | `hypermass-v1.0.0` = `5041be70` on `service-detection` | 2026-09-24 → 10-14 | #1–#10 |
| pre-release | `service-detection` up to `sd-freeze-2026-09-10` | 2026-08-21 → 09-21 | — |

---

## Hypermass 1.2 (`hypermass-1.2`, from 2026-11-24)

Branched from `hypermass-1.1` at `f4e002e3` (PR #32). The operator's
`compose.yaml` builds `engine` and `enum` from this branch.

**PR #33 (11-24) — session-end sweep: batched query restored; wappalyzergo
v0.3.11.**
- `e3bf31b1` Restore the session-end sweep's batched query. The write
  guard (PR #26) made `Session.DB()` return a wrapper, so the sweep's
  type assertion for PostgreSQL never matched; every session silently
  walked all its Done IPs one at a time (113,047 IPs and hours of
  end-work on one run, instead of seconds). The guard now has `Unwrap()`
  and the sweep unwraps; a sweep that cannot batch logs why; a chunk
  whose query fails sends only its own IPs to the walk (all remaining
  ones after three failures in a row). *Why:* found from the dashboard's
  end-work row (briefing §4.5).
- `16d3d5ce` wappalyzergo v0.3.8 → v0.3.11. No API change; 62 more
  fingerprints (7,724); `golang.org/x/net` v0.62.0 with it; same
  detections on sample responses; the Angular workaround is still needed.
  *Why:* the operator asked for the latest release (briefing §4.6).

**PR #34 (11-24) — `utility/dashboard.py`.** The operator's live terminal
dashboard, moved into the repository. Its end-work row now shows the
phase, `requeue (batch)` or `requeue (walk)`, progress, a whole-phase rate
and an ETC. *Why:* the old row could not show how far a requeue had got
(briefing §10.9).

**PR #35 (11-24) — operator scripts and config in `utility/`.**
`enum-companies.py`, `report-enumerated.py`, `update-domains.py`,
`config.yaml`, `datasources.yaml`, with every password and API key
replaced by `CHANGE_ME` because the repository is public. *Why:* keep the
operator's tooling with the code it drives (briefing §10.9).

**This change — documentation.** `docs/HYPERMASS_BRIEFING.md` rewritten
so every area of the fork gets equal weight, with a change-impact guide;
this changelog created.

---

## Hypermass 1.1 (`hypermass-1.1`, 2026-10-15 → 11-05)

**PR #11 (10-15) — active egress through an operator proxy** (`90bea54c`,
`2c091bc8`, `a5629f47`, `160a9865`, `0dde8982`). Every `-active`
connection (connect scans, HTTP probes, banner peeks, TLS harvests, JARM)
goes through `support.ActiveDialer` / `ActiveHTTPClient`: the proxy if
`active_proxy` is set; nothing at all if `active_strict` (default true);
direct only if strict is off. Nil-means-direct fallbacks removed; JARM
gated on `-active`; SOCKS "TTL expired" treated as a filtered port, not
a proxy failure; proxy-to-proxy CONNECT and an un-cancellable https proxy
handshake fixed from the source branch. DNS and passive sources never use
the proxy. `CheckActiveEgress` separated from `CheckSettings` so API
sessions are not affected by `CheckSettings`' wordlist rewriting. *Why:*
production must send active traffic only from approved egress, and fail
closed when it cannot.

**PR #12 (10-15) `c6600f24` — no mid-run proxy kill.** The session is
refused at start if the proxy is unusable; a proxy that dies mid-run just
makes active operations fail (nothing goes out directly). The refusal
reason is logged and reaches `oam_enum`. *Why:* stopping engines on proxy
failure is an external monitor's job, and the kill fired on a Tor exit
refusing a single port.

**PR #13 (10-15) `103e6efe` — `docs/engine_api.md`** and complete Swagger
docs. *Why:* Keith builds an orchestrator on the engine API.

**PR #14 (10-15) `46fa11cd` — four engine API bugs:** bulk asset add
crashed the engine on an asset the database refused; the single-asset
handler dropped the connection; a config with no `scope` panicked; the
log stream leaked a goroutine per message after a client left.

**PR #15 (10-25) `74a79405` — shared-provider ASNs.** An ASN announcing
more than 16 netblocks is shared infrastructure; under the cap only small
IPv4 blocks are admitted. *Why:* vistra.com (Cloudflare-fronted) reached
~500 provider netblocks, ~52k IPs and ~58k "open" ports via one provider
/24 → organization → ASN fan-out. (The cap became 500 in PR #21.)

**PR #16 (10-27) `e18dbbb8` — resolver override.**
`AMASS_ENGINE_RESOLVERS`, `AMASS_ENGINE_RESOLVER_QPS`,
`AMASS_ENGINE_WILDCARD_RESOLVER`. *Why:* AWS engines must use their own
resolvers, under the VPC resolver's per-interface limit, without a
rebuild.

**`ec0f29db` (10-29, upload) — `docs/hypermass_functions.sql`:**
`fqdn_by_domains`, `ips_by_domains`, `tplinks_by_domain`,
`other_domains_by_inscope_domains`, `techstack_by_domains`, used by the
operator's reports (briefing §10.8).

**PR #17 (10-31) `7a022f16` — privacy-proxy addresses.** Detection of
"On behalf of <domain>", whoisproxy/domainsbyproxy text, privacy mail
domains and hashed mailboxes; placeholder contacts skipped in every role;
an address used by more than 25 records is shared (not admitted, not
walked, not used for org dedup). *Why:* crayon.co's Amazon Registrar
proxy address (19,000+ records) pulled in hundreds of unrelated
organizations.

**PR #18 (10-31) `3389d040` — `enum -scope-json`.** Prints the session
scope as one `HYPERMASS_SCOPE {…}` line before termination (also under
`-silent` and on Ctrl-C). *Why:* the scope lives only in engine memory;
the operator's reports needed it.

**PR #19 (11-01) `845bc28d` — blue.cl / Salesforce:**
- hosting is not ownership: an in-scope netblock's registration expands
  to its registrant only when a contact email is on a seed domain;
- the shared-address count covers every stored variant of the same
  building;
- role names ("Domain Administrator") are not organizations.
*Why:* blue.cl grew into Salesforce Marketing Cloud (17 domains, two
/16s, 18,000+ IPs) through those three routes.

**PR #20 (11-01):**
- `f40144ca`: placeholder names ("N/A", "Private Person", "Internet
  Widgits Pty Ltd", …) treated like role names (`support.IsNonName`,
  `IsGenericName`). *Why:* RU-CENTER's "Private Person" linked every
  individually registered domain in the database.
- `a59c5b26`: domains admitted through registration records are queued
  as FQDNs (not DomainRecords); `scope.Add(TLSCertificate)` adds the CN's
  registered domain. *Why:* both expansion paths did almost nothing.

**PR #21 (11-02) `22e3ccbd` — Phase 1 scope vetoes.** Evidence against:
- `scope_vetoes` setting (`enforce` / `observe` / `off`) and the `scope
  decision` log;
- resolution alone no longer admits a netblock (N2); registration
  decides (`RegistrationVerdict`: owner / foreign / no information);
- foreign registrations declined; ASN cap raised to 500;
- per-IP RDAP for addresses in-scope names resolve to;
- care-of and mail-drop addresses (N1); masking phrases;
- merged certificates (M) excluded; certificate contact records keyed by
  issuer and subject;
- provenance (`via`, `from`, `distance`) logged on every addition.
*Why:* blue.cl's ~80,000 third-party addresses came in by resolution
alone; positive-link-only expansion had no way to say "this is someone
else's".

**PR #22 (11-02) `c94b044f` — per-IP RDAP handler moved to IPAddress
position 5.** *Why:* position 41 belongs to Port-Prefilter; the engine
refused to start. `load_test.go` now starts every plugin and fails on a
position conflict.

**PR #23 (11-02) `0b6bc615` — RDAP registrations stored under the range
they register.** *Why:* RDAP answers an announced /24 with the /22 that
covers it; storing the /22 range under the /24 CIDR was refused by
asset-db and the error discarded, so the record, contacts and ownership
were lost every run (Fiserv's First Data Asia-Pacific blocks).

**PR #24 (11-02) `2c23413d` — late-linked netblocks attributed;**
registrations spanning many CIDR blocks stored under the largest block
containing the netblock. *Why:* 203.17.32.0/24 was linked 27 minutes
after its siblings and stayed out of scope; AT&T's
99.10.64.0–99.75.191.255 range was not stored.

**PR #25 (11-02) `10dfacdc` — per-name database deadlines (15 s).**
*Why:* a whole batch shared one 30 s deadline; ~47,600 of Mailchimp's
IP-THC names were dropped and the lookup still marked.

**PR #26 (11-03) `1b13bfc1` — write guard.** *Why:* asset-db's single
writer runs each write under its caller's context; one caller's timeout
closed the connection and failed every other write in the batch
("savepoint: conn closed"; Blackbaud). asset-db may not be changed, so
the session wraps it.

**PR #27 (11-03) `7f81867b` — BGP.Tools' `<nil>` prefix is "no route",
not an error.** The /24 is recorded unrouted; its other addresses skip
BGP.Tools and IP-Netblock's 30 s wait. *Why:* 896 of 909 WHOIS errors on
Blackbaud; one query per second per unannounced address.

**PR #28 (11-03) `4420cab2` — reverse names and broken reverse zones.**
Forward DNS handlers skip `.arpa` names; a /24 whose reverse zone fails 5
lookups with none answered is skipped. *Why:* 17,897 of 18,007 DNS
failures on Blackbaud; each address was looked up four times.

**PR #29 (11-03) `16fda355` — dead forward zones, fill pacing, unrouted
scan skip.** A zone below the registered domain with 10 distinct failed
names and no answer is skipped; owned fills pause while the IPAddress
backlog is ≥ 2,048; unrouted addresses are not port-scanned. *Why:*
University at Buffalo: internal AD/wireless zones produced 6,931 forward
failures, and the 65k-address fill swamped the single writer.

**PRs #30, #31 (11-04/05) — docs:** MAINTAINERS moved to `docs/` and
updated; this briefing created, then its changelog and feature catalog
added.

**PR #32 (11-05) — wappalyzergo v0.3.2 → v0.3.8.** No API change; 21 more
fingerprints and faster body matching. `golang.org/x/net` (v0.61.0, which
0.3.8 requires) and the other `x/` modules moved with it. Same
detections on sample responses; the Angular workaround is still needed.
*Why:* requested by the operator (latest release).

---

## Hypermass 1.0 (2026-09-24 → 10-14)

**Direct commits on `service-detection`:**

- **09-24 `c7bbcd7b` — wappalyzergo v0.2.94 → v0.3.2.** Newer
  fingerprints; no API change.
- **09-25 `deeb9387` — engine build-info banner.** One `engine build
  info` line at start-up with the VCS revision and key dependency
  versions. *Why:* "is this engine the code I think it is?" cost time
  repeatedly.
- **09-25 `167ce735` — Angular from `ng-version`.** wappalyzergo never
  evaluates DOM rules, so modern Angular was never detected; Tech-Stack
  now reads the `ng-version` attribute itself.
- **09-25 `a1924644`, `7a8370de`; 09-26 `dd71fffa`; 10-09 `8aaff9fc`** —
  file modes and LF line endings normalised (web uploads set the
  executable bit and CRLF).
- **09-26 `e91b8686` — FQDN OSINT bypass gate.** Discovered (non-seed)
  names skip FQDN positions 20–40 and go straight to HTTP probing.
  *Why:* one-event-wide `Parallel` stages (crt.sh, AlienVault) held
  DNS-resolved names behind a slow scope domain. OSINT plugins refused
  discovered names anyway, so nothing was lost. Also fixed: a configured
  domain under another configured domain now gets OSINT. A start-up
  panic guards the position range.
- **09-26 `bc5297d1` — DNS lookups stop after 6 attempts (was 10).**
  Only timeouts, refusals and useless replies used the extra attempts.
- **10-03 `4c575575` — Product `website` and `cpe` properties** from
  Wappalyzer, stored like `icon`.

**PR #1 `fix/service-detection-review` (10-09)** — four fixes from a review:
- `fcbaea87`: the session-end hook runs **only** through `POST
  /end-work`, once per session. *Why:* Terminate, Ctrl-C and engine
  shutdown ran fills and sweeps before `Kill()`, so stopping a run started
  more scanning (sometimes for hours), and shutdown ran the hook twice.
- `b074e4ef`: names with `HasSLDInScope` (runtime scope domains) take the
  OSINT path in the bypass gate. *Why:* domains added during a run got no
  subdomain OSINT at all.
- `25f1bd43`: `support.IsNonRoutableAddress`; private, loopback,
  link-local, multicast, unspecified and reserved addresses are not
  scanned, banner-peeked, TLS-handshaked, or provenance-authorised. The
  DNS records are still stored.
- `d97a2555`: Protocol-Probes creates the `tls` Service only after a
  successful handshake; dispatches its Services (so Tech-Stack, JARM,
  Page-Links see them); names the port edge `tcp_port_<n>`; lowercases
  Product IDs (`support.ProductID`). *Why:* silent ports became empty
  Services; Services were invisible to enrichers; an unnamed edge
  duplicated or blanked HTTP-Probes' edge; "Nginx" vs "nginx" violated
  Postgres's unique natural key and was lost.

**PR #2 (10-09) `9bccf9e7`** — the session-end sweep counts runtime scope
domains as seed scope. *Why:* IPs of domains added by horizontals were
never swept.

**PR #3 (10-10) `2d396aff`** — the sweep's batch miss-list query starts
from the Done IPs (index probes per IP, chunks of 5,000, `OFFSET 0`
subqueries) instead of a `LIKE` join on `reverse_fqdn`. *Why:* the join
read the whole `fqdn` table and passed asset-db's 60 s statement timeout;
23 s → 0.3–5.3 s on a 6M-FQDN database.

**PR #4 (10-10):**
- `33e2274d`: Port-Prefilter declares `Transforms: Service`. *Why:* with
  no Transforms it never ran under `IPAddress->ALL`, so fill IPs and
  `-addr`/`-cidr` seeds were never scanned (owned /22: 17 → 1,021 of
  1,022 addresses scanned).
- `40b658d5`: Protocol-Probes passes the parsed leaf certificate on its
  event. *Why:* certificates from IMAPS, LDAPS and the like were stored
  without their CN/SAN name links.

**PR #5 (10-10) `d67f048e` — mark OSINT lookups only when the source
answered.** URLScan, HackerTarget, crt.sh, CertSpotter, SubdomainCenter,
DNSDumpster, AlienVault, DNSRepo, RapidDNS, IP-THC. New
`support.HTTPLookupFailure` and `support.LogLookupFailure`. *Why:* a
rejected key, a quota notice, a 429 or a timeout was recorded as "looked
up, nothing found" and suppressed the source for the whole TTL, in later
sessions too, usually with no log line.

**PR #6 (10-11) `22c46ab0` — Prospeo on its current API.** The old
endpoints no longer exist; one domain could spend the whole credit
balance; failed calls were marked done. Now account-information →
search-person → bulk-enrich-person, bounded per domain by
`max_emails_per_domain` and `min_remaining_credits` (new data-source
`options` map).

**PR #7 (10-11):**
- `abaa4431`: byte-order marks stripped (they broke `go test -cover`),
  gofmt, a shadowed `ttl` in `ClaimNext` renamed (no behaviour change).
- `b292f913`: RDAP (netblock, ASN), WHOIS (domains) and GLEIF mark only
  when answered; GLEIF's non-200 no longer reads as a confidence-100
  match. *Why:* with a 30-day Netblock RDAP TTL, one timeout hid a
  block's ownership evidence for a month.
- `cb6071a3`: in-scope PTR names of owned-block IPs get a direct
  `IP -ptr_record-> host` edge and an `apex -node-> host` edge (skipped
  for names that spell the address). Horizontals' IP handler follows the
  `.arpa` PTR edge, not the newest edge. *Why:* PTR-only hosts in owned
  space were invisible to domain queries.

**PR #8 (10-14) `175906d5` — URLScan sends its own User-Agent.** *Why:*
urlscan.io answers browser User-Agents with 429 before checking the key;
every search failed for weeks with the quota at 0%, and the host was
eventually IP-blocked.

**PR #9 (10-14) `5e026040` — netblock admission needs both a small block
and an in-scope name.** Restores `HasInScopeFQDN` beside the /20 size
check. Horizontals now logs every asset it adds. *Why:* the 09-21
replacement admitted CDN and SaaS /24s (Cloudflare, Bitly, Stripe);
horizontals then put those companies and their domains in scope, and
small targets grew to tens of thousands of names.

**PR #10 (10-14) `b36c03d3` — PassiveTotal no longer loaded.** It never
sent a request, and the API went to Microsoft with RiskIQ.

**Release 1.0:** tag `hypermass-v1.0.0` on `5041be70`. `176be5e5`
uploaded MAINTAINERS to `service-detection`, which is now frozen.

---

## Pre-release: web uploads (2026-08-21 → 09-21)

| Date | Area / files | What changed | Why |
|---|---|---|---|
| 08-21 | `api/certspotter.go`, `api/dnsdumpster.go`, `api/subdomaincenter.go`, `api/commoncrawl.go`, `api/urlscan.go`, `load.go` | Five subdomain sources added and registered (CertSpotter, DNSDumpster, SubdomainCenter, CommonCrawl, URLScan). | v5 had lost sources that v4 had (SubdomainCenter, CommonCrawl) or never had them; more passive coverage per apex (briefing §6.2). |
| 08-21 | `pagelinks.go` | Page-Links plugin: hostnames from fetched page bodies, with URL→File→URL provenance. | Find names linked from the target's own pages, and record which page they came from (briefing §4.8). |
| 08-21 | `support/fingerprinting.go`, `http_probes/plugin.go` | Error logging added and removed the same day; no net change. | — |
| 08-22 | `enrich/techstack.go`, `go.mod` | Tech-Stack plugin (Wappalyzer over fetched pages) and the `wappalyzergo` dependency. | Identify products and versions on web services (briefing §4.6). |
| 08-23 | `api/server/server.go`, `v1/handlers.go` (`843d61b7`) | `GET /sessions/{token}/backlog` and `GET /handler-stats`. | A live dashboard of backlog, connections and handler cost (briefing §10.1). |
| 08-23 | `api/urlscan.go` (`d6f0e90e`) | URLScan's ASN handler removed; PTR hostnames validated before storage. | The ASN search returned 58,000+ unrelated names on cloud-hosted targets. |
| 08-23–24 | `whois/fqdn_lookup.go`, `whois/rdap.go`, `whois/domain_record.go`, `whois/plugin.go` | Domain lookups try RDAP first, then port-43 WHOIS. | Many registries have stopped answering port-43 WHOIS (briefing §6.5). |
| 08-24–28 | `service_discovery/protocol_probes/*`, `go.mod` (recog-go) | Protocol-Probes: banner peek, classification, Recog matching, TLS certificate harvest, Product storage. Many iterations. | Identify non-HTTP services (SSH, mail, FTP, TLS-only ports) (briefing §4.4). |
| 08-25 | `http_probes/ipaddr_endpoint.go`, `plugin.go` | IP-endpoint probing reworked (banner pre-peek, instance count). | Prepare HTTP probing to read pre-filter results. |
| 08-26 | `ip_netblock.go`, `whois/bgptools/netblock.go` | **New behaviour:** discovered netblocks added to the session scope (first unconditionally, then gated on `HasInScopeFQDN`). Stock never did this. | `Scope.Netblocks()` was otherwise always empty for discovered blocks. This path later caused the CDN leaks (see 09-21, PR #9, PR #21). |
| 08-26 | `dns/ip.go`, `dns/reverse.go` | Provenance authorization (the exact IP an in-scope name resolves to is added to scope); sweep sizing tied to FQDN scope only; DNS-Reverse's PTR sweep removed. | Scan the target's hosts on shared infrastructure without admitting the whole provider block (briefing §8). |
| 08-26 | `sessions/session.go` | Session semaphore deadlock fixed (lock not held across a blocking acquire). | A full semaphore froze every plugin (MAINTAINERS 7.1). |
| 08-26–27 | `support/database.go` | `ResolvingFQDNs` / `HasInScopeFQDN` helpers (hydrating edge targets by ID). | The first version returned nothing because edges carry only IDs. |
| 08-30 | `port_prefilter/plugin.go`, `support/portscan.go`, `http_probes/*` | Port pre-filter: TCP connect scan stored as `open_port` tags; HTTP-Probes read them. | Stop probing every configured port on every IP; ~99.9% of probes skipped, a 48 h run became 6 h (briefing §4.1). |
| 08-31 | `internal/net/network.go`, `sessions/session.go`, `types/sessions.go`, `v1/handlers.go` | `ScanSem` (3,200 slots), `Semaphore.InUse()/Cap()`, backlog API connection fields. | Keep connect-scan sockets from crowding plugin sockets, and make both visible. |
| 08-31 | `support/portfreq_data.go`, `support/portpriority.go` | nmap frequency ordering of open ports; decoy detection (>50 open ports → 90 s budget). | Probe likely ports first; bound time on WAFs that answer every port. |
| 09-01 | `support/portscan.go`, `support/database.go` | `PruneStalePortData` (prune by value after a full scan) and the `since` read filter. | `open_port` tags accumulated forever, reporting ports open that had closed. |
| 09-01 | `protocol_probes/service.go`, `enrich/techstack.go` | Product/ProductRelease storage, including the Service→ProductRelease `product_used` edge. | Per-host versions are otherwise unrecoverable (Product is global). |
| 09-02 | `whois/bgptools/plugin.go` | Read deadline on the WHOIS socket; mutex released around the query ("Stage 1"). | A silent server hung the whole IP pipeline; the mutex serialised all lookups to 11/min (MAINTAINERS 7.2, 7.3). |
| 09-02 | `jarm.go` | Fingerprint target fixed (`asset: a`), protocol compared case-insensitively. | JARM produced zero fingerprints in every run (MAINTAINERS 4.4). |
| 09-02–04 | `pagelinks.go` | Provenance chain and origin anchor; fragments stripped; 1,000 URLs per page. | Answer "which page linked this host" from the graph. |
| 09-04 | `api/rdap/ipnet.go`, `ip_netblock.go` | First attempt at admitting a netblock by its registration contacts (capped at /21). Later reverted and redone as the owned-netblock fill (09-06). | Target-owned blocks with no resolving names were never in scope. Reverted because ownership was decided after the IPs had passed their consumers (MAINTAINERS 10.7). |
| 09-05 | `protocol_probes/banner_normalize.go`, `recog_client.go` | Banner normalisation (greeting stripping, line candidates). | Recog matches the field after the protocol greeting; raw banners matched almost nothing. |
| 09-05–06 | `protocol_probes/sweep.go`, `engine.go`, `sessions/manager.go`, `backlog.go`, `backlogdb/backlog.go`, `types/*` | Session-end hook; Protocol-Probes sweep of IPs whose ports were found after Protocol-Probes ran; `Backlog.ListDone`; `Dispatcher.ResubmitEvent` exposed. | IPs reached Protocol-Probes before their scan finished and were never probed (MAINTAINERS 10.4). |
| 09-06 | `support/owned_netblock.go`, `support/endwork_progress.go`, `api/rdap/ipnet.go`, `ip_netblock.go`, `bgptools/netblock.go` | Owned-netblock attribution (RDAP contact email on a seed domain → scope at any size) and the fill (every address synthesised and dispatched). End-work progress reporting. | The 10.7 design: scan target-owned space that no name points at (briefing §7.3). |
| 09-06–07 | `internal/enum/cli.go`, `api/client/v1/client.go`, `v1/handlers.go`, `server.go` | `POST`/`GET /sessions/{id}/end-work`; enum waits for the hook before terminating; log stream read in its own goroutine. | The hook needs the session alive; a busy log stream starved enum's idle timer (briefing §10.4). |
| 09-08, 09-11 | `api/thc.go` | IP-THC plugin (passive DNS from ip.thc.org: subdomains, reverse CNAMEs, owned /24s). | High-volume free source of historical names (briefing §6.2). |
| 09-09, 09-12 | `registry/pipelines.go`, `internal/enum/cli.go` | Completed elements Acked when the dispatcher channel is full; handler panics recovered and Acked; enum exits 2 minutes after the hook is done if WorkItems never go idle. | Stranded leases kept enum waiting forever (MAINTAINERS 7.4). |
| 09-10 | `protocol_probes/sweep_query.go` | Postgres batch query for the sweep's miss list, with a serial fallback. | The per-IP walk over thousands of Done IPs was slow. |
| 09-15 | `support/org/find.go`, `org.go` (`0665f470`) | Org dedup ancestor walks bounded (labelled edges, 10 hops, 256 nodes, 32 same-name orgs, 2 s); global lock held only for the final check and create. | "Fix OOM condition caused by unbounded merge": unbounded walks exhausted memory (briefing §7.9). |
| 09-17 | `load.go` (`86388fa2`, `3c47c91b`) | **Wayback, Bing and DuckDuckGo removed from the plugin list** (their files remain). | Not recorded; the commit has no message. Ask the operator before re-adding. |
| 09-19 | `api/alienvault.go`, `load.go` | AlienVault OTX passive DNS. | Additional passive source, ~5 names per apex (briefing §6.2). |
| 09-20 | `api/crtsh.go` | crt.sh's source name fixed (it said "HackerTarget"). | crt.sh and HackerTarget shared one TTL slot; HackerTarget was effectively dark (MAINTAINERS 7.5). |
| 09-21 | `scrape/dnshistory.go`, `scrape/sitedossier.go` | Page loops stop on a non-2xx status or a page with no names. | A blocked source used 19 rate-limiter tokens per seed for nothing (MAINTAINERS 7.6). |
| 09-21 | `ip_netblock.go`, `bgptools/netblock.go`, `support/database.go`, `support/owned_netblock.go` (`038a978e`, `97c6794b`, `b34d02dc`) | Netblock admission given a /20 size limit. **The size check replaced `HasInScopeFQDN` instead of joining it**, and the helper was deleted. | Meant to stop whole cloud /10–/12s entering scope. The replacement admitted every small block any IP fell in, and stayed latent until PR #9 (10-14). |
