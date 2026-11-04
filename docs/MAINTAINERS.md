# Maintainer's Guide — Hypermass (`prisoner881/hypermass`)

**Audience.** A developer who has never seen the Amass codebase or this
fork, and who needs to maintain, extend, or debug it.

**How to read this.** Part 1 is background on stock Amass — skip it if
you already know the engine. Parts 2–8 document what the fork changed up
to release 1.0 and why. Part 9 is operational knowledge that isn't in any
code comment. Part 10 is the list of known problems, and Part 11 is the
debugging methodology that actually works on this system. Part 12 covers
releases and naming. **Part 13 covers everything merged on `hypermass-1.1`
since release 1.0**: active-egress proxying, the engine API, the scope
overhaul (vetoes, registration-based ownership), and the database and DNS
fixes found on large runs. Where Part 13 changes something an earlier part
describes, the earlier part says so and points to it. The appendices are
reference tables you'll want open while working.

**Companion document.** `docs/HYPERMASS_BRIEFING.md` is a hand-off brief
for whoever picks up development next: working conventions, the
environment, open work, and the agreed plan for the remaining scope
phases. Read it before changing anything.

Everything here was verified against the code at the time of writing.
Where a claim comes from a production measurement rather than the source,
it says so.

**Name.** The fork is called **Hypermass** from release
`hypermass-v1.0.0` on (Part 12). The repository was renamed from
`prisoner881/amass`; the old URL redirects. The code itself was not
rebranded: the banner, `-version` and the visualisation titles still say
"OWASP Amass v5.1.1", the binaries keep their names, and the Go module
path is still `github.com/owasp-amass/amass/v5`.

**Branches.**

| Branch | State |
|---|---|
| `hypermass-1.1` | **Active development.** Everything since 1.0 (PRs #11–#29). Part 13. |
| `service-detection` | **Frozen** at `176be5e5` (release 1.0, `hypermass-v1.0.0` = `5041be70`, plus the upload of this guide). Never commit to it. |

**This revision** covers everything merged to `hypermass-1.1` up to
`e521102b` (PR #29). New since the previous revision (the 1.0 one):

- **Active egress** (13.1): every `-active` connection goes through an
  operator proxy, or nowhere; DNS and passive sources never do.
- **Engine API** (13.2): `docs/engine_api.md`, four API bug fixes, and
  `enum -scope-json`.
- **DNS resolver override** (13.3): `AMASS_ENGINE_RESOLVERS`,
  `AMASS_ENGINE_RESOLVER_QPS`, `AMASS_ENGINE_WILDCARD_RESOLVER`.
- **Scope overhaul** (13.4): shared-provider ASNs, privacy proxies and
  shared addresses, role and placeholder names, hosting is not ownership,
  and the `scope_vetoes` framework: resolution alone no longer admits a
  netblock; registration decides ownership.
- **RDAP registrations** (13.5) stored under the range they register.
- **Database writes** (13.6): per-name deadlines and the write guard
  around asset-db's single writer.
- **Unrouted space and dead DNS zones** (13.7, 13.8), and **owned-fill
  pacing** (13.9).

Release-1.0 changes, from the previous revision:

- **Scope:** the netblock admission gate now requires both a small block
  *and* an in-scope name (6, 6.2), after the size-only gate let
  CDN/SaaS owners' domains into scope; horizontals logs every scope
  addition (6.6); private and non-routable addresses are no longer scanned
  or authorised (6.3); in-scope PTR names on owned-block IPs are linked
  directly (6.4); the FQDN OSINT bypass gate and runtime scope domains
  (6.5).
- **Service detection:** Port-Prefilter gated by `Service` (3.3);
  Protocol-Probes Service creation, dispatch, port-edge and product-ID
  fixes, and certificate names for its leaf certificates (4.2); Tech-Stack
  website/CPE properties and lowercase product IDs (4.3).
- **Data sources:** lookups are marked done only when the source answered
  (4.8); Prospeo on its current API (4.9); URLScan's User-Agent (4.10);
  RDAP, WHOIS and GLEIF outcome handling (4.11); PassiveTotal no longer
  loaded (4.12); THC's IP data clarified as passive DNS (4.6).
- **Session end:** the hook runs only through `end-work`, never on
  terminate or shutdown (9.2.1); the sweep includes runtime scope domains
  and its batch query no longer times out (10.4).
- **Smaller fixes:** DNS lookups stop after 6 attempts (7.7); byte-order
  marks, gofmt and a shadowed lease variable (7.4, 7.8).
- **Operations:** where each kind of log line goes (9.1), `datasources.yaml`
  traps (9.6), `enum -silent` hiding errors (9.7).

The active-proxy work was ported onto 1.0 as `hypermass-1.1` (13.1); the
old `merge/active-proxy-egress` and `feature/active-proxy-egress` branches
and their merge notes in Part 6 are historical.

---

# Part 1 — Orientation: how stock Amass works

You cannot maintain this fork without understanding four upstream
concepts. They are not well documented upstream, and most of the fork's
subtleties are consequences of them.

## 1.1 The engine, sessions, and scope

A **session** is one enumeration. It owns a scope, a backlog, a database
handle, and a network semaphore. `engine/sessions/session.go` builds it.

The **scope** (`engine/sessions/scope/`) is the set of assets considered
to belong to the target organization. It starts as the domains supplied
on the command line and **grows during the run**. `scope/assoc.go`
implements this: a candidate asset is admitted if it can be associated
with something already in scope at sufficient confidence, and each
admitted asset then becomes evidence for admitting others.

This matters more than it looks. The seed domain list is not a filter —
it is the evidence base for expansion. Splitting one enumeration into
several smaller ones is **not** equivalent, because each fragment loses
the associations that the others would have supplied. This came up as a
proposed workaround for a performance problem and had to be rejected for
exactly this reason.

## 1.2 The event pipeline

The engine is not a linear program. It is a set of **pipelines**, one per
OAM asset type (FQDN, IPAddress, Service, URL, …), built by
`engine/registry/pipelines.go:BuildAssetPipeline`.

An **event** is one asset moving through one pipeline. Plugins register
**handlers** at numbered **positions** (1–50). Each position becomes a
pipeline **stage**, and an event traverses stages in ascending position
order.

**Positions are completion barriers, not priority hints.** An event
finishes position N entirely before entering N+1. The whole
`port_prefilter` design (Part 3) depends on this guarantee.

Three stage types, chosen automatically:

| Handlers at position | `MaxInstances` | Stage type | Events in flight |
|---|---|---|---|
| 1 | > 1 | `DynamicPool` | up to `MaxInstances` |
| 1 | ≤ 1 | `FIFO` | 1 |
| > 1 | *ignored* | `Parallel` | **1** |

`DynamicPool.executeTask` takes a token, spawns a goroutine, and returns
immediately — so the stage keeps reading input. `FIFO` and `Parallel` are
synchronous and therefore process one event at a time.

**`Parallel` ignores `MaxInstances` entirely.** If two or more handlers
share a position, every one of them silently loses its concurrency
setting. This is an upstream behaviour with significant performance
consequences; see Part 10.1.

Concurrency constants (`engine/plugins/support/support.go`):

```go
MinHandlerInstances  = 4
MidHandlerInstances  = 16
HighHandlerInstances = 32
```

## 1.3 The backlog and dispatcher

Plugins do not pass results to the next stage. When a plugin discovers
something, it writes it to the database and calls `DispatchEvent`, which
puts the new asset into the **backlog** — a per-session SQLite database
(`engine/sessions/backlogdb/`). The event itself continues down its own
pipeline unchanged.

The **dispatcher** (`engine/dispatcher/dispatcher.go`) pumps work from
the backlog into pipeline queues, respecting per-asset-type limits:

| Asset type | MaxQueued | HighWater | LowWater |
|---|---|---|---|
| FQDN, IPAddress | 200 | 175 | 100 |
| Service, TLSCertificate, URL | 100 | 75 | 25 |
| everything else | 20 | … | … |

`runPump` refills on a 10-second tick or when woken by
`completedCallback`, which also **acks** the event in the backlog. An
event's lease is held from dispatch until it finishes traversing its
pipeline.

Consequence for debugging: the dashboard's `leased` column is *not* the
number of events executing. It is the number claimed from the backlog and
not yet acked — most of them sitting inside pipeline stages.

## 1.4 The database (asset-db and OAM)

Two external repos matter:

- **`owasp-amass/open-asset-model`** — the data model. Asset types, and
  crucially `relation.go`, which declares **which edge labels are valid
  between which entity types**. `CreateEdge` validates against this via
  `ValidRelationship` and silently rejects anything not declared.
- **`owasp-amass/asset-db`** — the persistence layer.

### Schema shape (this trips people up)

```
entity(entity_id, etype_id → entity_type_lu, natural_key, table_name, row_id)
edge(edge_id, etype_id → edge_type_lu, label, content jsonb, from_entity_id, to_entity_id)
entity_tag(tag_id, entity_id, ttype_id, property_name, property_value, content jsonb)
edge_tag(tag_id, edge_id, ttype_id, property_name, property_value, content jsonb)
```

**`entity` has no `content` column.** The asset data lives in per-type
tables — `fqdn`, `ipaddress`, `service`, `tlscertificate`, `product`,
`url`, `file` — reached via `row_id`. `natural_key` is the canonical
display string.

**There is no `last_seen` column.** Use `updated_at`. Tags expose
`property_name` and `property_value` as real columns, not only inside
`content`.

Two behaviours you must know:

- `entity_get_tags` filters on **`updated_at >= since`**, not
  `created_at`.
- `entity_tag_upsert` conflicts on
  `(entity_id, ttype_id, property_name, property_value)` and does
  `SET updated_at = now()`. So re-storing the *same* value refreshes the
  timestamp, while storing a *different* value **adds a second row**.
  This is why `open_port` tags accumulate one row per distinct port.

### Connection pooling — it is not GORM

`gorm.io/gorm` appears in `asset-db`'s `go.mod` but is used only by an
example test. All real queries go through **pgx v5 + pgxpool**, wrapped
in a custom batching `Worker`.

Per engine instance, fixed at compile time and unreachable from config:

| Pool | Connections |
|---|---|
| reader | 3 |
| writer | 1 |
| migration (startup only) | 1 |

`postgres.New(dbtype, dsn)` builds the `WorkerConfig` literals
internally; `pool_max_conns` in the DSN is parsed and then overwritten.
The writer batches up to 100 statements per transaction with a 1 ms max
delay, using savepoints, and no session-scoped features — so the
workload is safe for pgBouncer **transaction** pooling.

### Plugin gating: transformations and TTL

Two independent gates decide whether a handler's callback runs:

1. **Transformation check** — `config.yaml`'s `transformations:` block.
   `handlerTask` calls `CheckTransformations(from, h.Transforms...)`; if
   the from→to pair isn't permitted, the callback never runs.
2. **TTL check** — most plugins call `AssetMonitoredWithinTTL(...)` and
   skip if the asset was processed recently, then `MarkAssetMonitored`
   when done. The window comes from `TTLStartTime`, defaulting to
   `default_transform_values.ttl` (1440 minutes).

The TTL mark is written as an `entity_tag` with
`property_name = 'last_monitored'` and `property_value = <source name>`.
This is the single most useful table for debugging what ran and when.

---

# Part 2 — What this fork changes

Against the upstream merge base the fork is no longer a 49-file delta.
Count files when you need a number; the table below is the map.

| Area | Files | Part |
|---|---|---|
| Port pre-filter subsystem | `support/portscan.go`, `support/portpriority.go`, `support/portfreq_data.go`, `service_discovery/port_prefilter/` | 3 |
| Non-HTTP service detection | `service_discovery/protocol_probes/` (incl. session-end sweep) | 4 |
| HTTP probing changes | `service_discovery/http_probes/` | 4 |
| Web tech fingerprinting | `enrich/techstack.go` | 4 |
| JARM fix | `jarm.go` | 4 |
| Page-link provenance | `pagelinks.go` | 5 |
| Scope correctness | `ip_netblock.go`, `whois/bgptools/netblock.go`, `dns/ip.go`, `dns/reverse.go`, `support/database.go` (`HasInScopeFQDN`), `support/nonroutable.go`, `horizontals/plugin.go` (scope-addition log), `horizontals/ipaddr.go` | 6 |
| FQDN OSINT bypass gate | `registry/osint_bypass.go`, `registry/pipelines.go` | 6.5 |
| Owned-netblock fill and PTR attribution | `support/owned_netblock.go` (incl. `IPInOwnedNetblock`), `dns/reverse.go`, `dns/apex.go` | 6 |
| Session-end hook | `engine/engine.go`, `sessions/manager.go`, `internal/enum/cli.go` | 9 |
| Upstream defect fixes | `whois/bgptools/`, `sessions/session.go`, `registry/pipelines.go` | 7 |
| OSINT plugins | `api/certspotter.go`, `api/commoncrawl.go`, `api/dnsdumpster.go`, `api/subdomaincenter.go`, `api/urlscan.go`, `api/thc.go`, `api/alienvault.go`, `api/prospeo.go`, `api/crtsh.go` (7.5), `scrape/dnshistory.go` + `scrape/sitedossier.go` (7.6), `whois/rdap.go` | 4, 7 |
| Lookup outcome rule | `support/lookup.go` (`HTTPLookupFailure`, `LogLookupFailure`), applied in the OSINT, RDAP, WHOIS and GLEIF plugins | 4.8, 4.11 |
| Product identity | `support/product.go` (`ProductID`, `ProductReleaseName`) | 4.3 |
| Dashboard API | `api/server/v1/handlers.go`, `api/server/server.go` | 8 |
| Support helpers | `support/database.go`, `internal/net/network.go` | 3 |
| Active egress (1.1) | `internal/net/active_egress.go`, `support/active.go`, `config/active_proxy.go`, the active plugins | 13.1 |
| Engine API (1.1) | `api/server/v1/`, `pubsub/logger.go`, `internal/enum/scope_json.go`, `docs/engine_api.md` | 13.2 |
| Resolver override (1.1) | `support/resolvers.go`, `internal/amass_engine/cli.go` | 13.3 |
| Scope vetoes and ownership (1.1) | `support/scope_decision.go`, `support/registration_verdict.go`, `support/care_of.go`, `support/merged_cert.go`, `support/shared_location.go`, `support/role_names.go`, `whois/privacy_detect.go`, `horizontals/`, `api/rdap/ipaddr.go`, `config/scope_vetoes.go` | 13.4 |
| RDAP registration storage (1.1) | `api/rdap/netblock.go`, `api/rdap/ipnet.go` | 13.5 |
| Database write path (1.1) | `support/database.go` (`storeEach`), `sessions/write_guard.go` | 13.6 |
| Unrouted networks, DNS caps, fill pacing (1.1) | `support/unrouted.go`, `support/reverse_dns.go`, `whois/bgptools/`, `dns/`, `support/owned_netblock.go`, `support/portscan.go` | 13.7–13.9 |

New dependencies: `projectdiscovery/wappalyzergo` **v0.3.2** (web tech
fingerprints; bumped from v0.2.94 — see 4.3), `runZeroInc/recog-go` (service banner fingerprints,
embedded — no external service), `golang.org/x/net` (HTML tokenizer).

---

# Part 3 — The port pre-filter subsystem

This is the largest and most performance-critical addition. Read this
part before touching anything in `support/`.

## 3.1 The problem it solves

Stock `http_probes` probed every port in `config.yaml`'s `ports:` list
against every in-scope IP. On a large estate that is millions of
connection attempts, almost all to closed ports.

The pre-filter adds a cheap TCP connect-scan stage **ahead** of the
expensive probes, so they only probe ports confirmed open. Measured on a
large public university: **~99.9% of ports skipped**, and enumeration time
dropped from ~48 hours to ~6 hours when first introduced.

## 3.2 Architecture

```
IPAddress pipeline:
  position 41  port_prefilter      HighHandlerInstances (32)   ← scans
  position 42  http_probes/ipaddr  HighHandlerInstances (32)   ← reads
  position 43  protocol_probes     MidHandlerInstances  (16)   ← reads

FQDN pipeline:
  position 41  http_probes/fqdn    MidHandlerInstances  (16)   ← scans + reads
```

Position ordering is load-bearing: 41 completes before 42 and 43 for the
same event.

`port_prefilter/plugin.go` is a thin wrapper. All logic lives in
`support/portscan.go` so that `http_probes` can reach it from the FQDN
pipeline.

## 3.3 Key entry points (`support/portscan.go`)

**`EnsureOpenPortsScanned(e, ent, dial) []int`** — the single shared
entry point. Checks scope, checks `AssetMonitoredWithinTTL`, and either
returns cached results or performs a scan. Concurrent calls for the same
entity are collapsed by a `singleflight.Group` keyed on `ent.ID`.

**`OpenPortsForFQDN(e, ent, dial) []int`** — resolves an FQDN to its IPs
and calls `EnsureOpenPortsScanned` for each, **sequentially**. Used by
`fqdn_endpoint.go`. This is *active triggering*: the FQDN pipeline causes
scans rather than only reading results.

**`PrefilterTTLStartTime(session)`** — the single source of truth for the
freshness window. Both the "should we rescan" decision and the "what
counts as fresh" read derive from this, so they cannot disagree.

**`scanPorts`** — the actual scan. Bounded by `maxConcurrentPortsPerIP`,
2-second dial timeout, no NetSem acquisition (see 3.5).

**Gating.** The Port-Prefilter handler declares `Transforms: Service`
(`prefilterTransforms`), the same rule as the plugins that read its
`open_port` tags. So the stock `IPAddress->ALL` turns it on and excluding
Service turns it off along with HTTP-Probes and Protocol-Probes. Before
this, with no `Transforms`, it ran only when `config.yaml` named
`IPAddress->Port-Prefilter` explicitly, and IPs that no in-scope name
resolves to (owned-netblock fill) were never scanned. Measured on a
community college's owned `/22`: 1,021 of 1,022 IPs scanned after the
change, 17 before.

**Non-routable addresses** (RFC 1918, RFC 4193, loopback, link-local,
multicast, unspecified, plus `amassnet.ReservedCIDRs`) are never scanned:
`EnsureOpenPortsScanned` checks `support.IsNonRoutableAddress` first.

## 3.4 The constants, and why they are what they are

```go
const PortPrefilterScanTimeout = 2 * time.Second   // portscan.go
const maxConcurrentPortsPerIP  = 100               // portscan.go
const LikelyDecoyThreshold     = 50                // portpriority.go
const DecoyTimeBudget          = 90 * time.Second  // portpriority.go
```

`maxConcurrentPortsPerIP` has a history that must be understood before
changing it. It is documented at length in the source; the short version:

- Originally 25.
- Raised to 100 → **engine-wide silent failure**. 32 handler instances ×
  100 ports = 3,200 concurrent sockets against a 1,024 file-descriptor
  limit. Every plugin needing a socket failed, silently, because
  `scanPorts` does not acquire NetSem and nothing else noticed.
- Reverted to 25.
- Raised to 100 again **only after** the container's `nofile` limit was
  raised to 8,192 in `compose.yaml`.

Current worst case: 3,200 (`port_prefilter`) + 1,600 (`fqdn_endpoint`,
16 × 100) + 500 (NetSem) ≈ **5,300 against 8,192**.

**The 8,192 ulimit is a property of the deployment, not the code.** Any
environment that doesn't set it inherits Docker's 1,024 default and will
reproduce the original failure. In Kubernetes this is a pod-spec concern.

Measured effect of 25 → 100 on the same target: prefilter throughput
1.90 → ~4.0 IPs/sec, total runtime 264 → 163 minutes, and — unexpectedly
— **asset discovery improved**, from a typical 29–33k in-scope FQDNs to
39,363 at 96.2% resolving. The reason is that `fqdn_endpoint`'s handler
slots were previously pinned inside `scanPorts` (9.4 s average
occupancy), starving every other plugin on the FQDN pipeline.

## 3.5 Two connection budgets: NetSem and ScanSem

Every **plugin HTTP/API/probe** socket goes through the session-wide
`NetSem` (default 500). **`scanPorts` does not.** It uses a second
semaphore, `Session.ScanSem()`, cap `MaxScanConns = 3200`
(`internal/net/network.go`). That is 32 prefilter instances × 100
concurrent ports, so the pre-filter can run at the 3.4 § design point
without starving OSINT.

Dashboard labels:

- `NetSem: X/500` — plugin / HTTP / TLS probes
- `ScanSem: Y/3200` — connect-scan only

The old `Connections: X/500` reading 0 during a scan was not a bug; it
was ScanSem traffic that NetSem never saw. Do not fold the two budgets
together. A 3,200-slot NetSem would let a burst of `http_probes` contend
with SYNs.

`scanPorts` still does not take NetSem. The FD math in 3.4 is unchanged
(`nofile` 8192). ScanSem only makes the scan load visible and keeps it
from crowding plugin sockets.

## 3.6 Port ordering and decoy detection

`support/portfreq_data.go` is a generated Go map of real `nmap-services`
frequency data (8,380 TCP ports). `SortByFrequencyDesc` orders ports so
the most likely ones are probed first.

Note the sort is applied by the **consumers** (`ipaddr_endpoint`,
`fqdn_endpoint`, `protocol_probes`) to the returned open-port list, not
inside `scanPorts` — because `scanPorts` always scans the full list and
cannot be truncated, whereas probing under a decoy deadline can.

**Decoy detection** flags IPs answering on implausibly many ports —
Imperva-style WAFs that SYN-ACK everything. `IsLikelyDecoy(n)` returns
`n > 50`; flagged assets get a bounded `DecoyTimeBudget` via
`DecoyTimeoutChannel`, which uses the `nil`-channel `select` idiom so
non-flagged assets stay unbounded.

Observed once in production, on a mid-sized state university: two WAF
addresses in the same provider /16 answering on 59 of the top-100 ports,
including nonsense like 49152–49157, 6000/6001, and 9100. Detection
worked. See Part 10.3 for why it didn't help.

## 3.7 Storage and pruning

`StoreOpenPort` writes one `open_port` entity tag per open port;
`StoreOpenPortCount` writes a single `open_port_count`.

`PruneStalePortData(ctx, session, ent, keep)` deletes any `open_port` tag
whose port isn't in `keep`, and any `open_port_count` whose value isn't
`len(keep)`. Called from `EnsureOpenPortsScanned` **after** storing, and
only when `ctx.Err() == nil`.

Three design points, all deliberate:

- **Prune by value, not timestamp.** A timestamp cutoff would compare a
  Go clock against Postgres's `now()`; clock skew could delete rows
  written seconds earlier. Value comparison has no clock dependency.
- **Write first, then prune.** Delete-then-write would leave a window
  where the IP has no ports at all, and a reader landing in it would skip
  probing and mark itself monitored for the full TTL.
- **Never prune after a partial scan.** A cancelled context means
  `scanPorts` returned early; pruning against that would delete open
  ports that were simply never reached.

**Why this exists.** Because the tag upsert key includes
`property_value`, storing a *different* port adds a row rather than
replacing one, so `open_port` tags would otherwise accumulate forever and
a port open once would be reported open indefinitely. That produces
**false positives** — the one place in this pipeline where the error runs
in that direction, and the reason this was worth fixing rather than
living with. It only bites on a persistent database across repeated
enumerations, which is the production configuration.

**Two layers, both shipped.** `PruneStalePortData` fixes it at the
storage layer. Separately, `OpenPortsForIP` takes a required `since`
parameter (from `PrefilterTTLStartTime`) and filters at read time. The
read filter is redundant in the normal path and deliberately kept: it
covers the cases pruning cannot — a delete that errors, a pass that
skipped pruning because the context was cancelled, or a database restored
from an older backup. Storage correctness and read correctness therefore
fail independently rather than together.

Safe to filter on `since` because the underlying lookup tests
`updated_at`, not `created_at`, and the upsert refreshes `updated_at` on
conflict — so a still-open port re-confirmed by any later scan stays
visible, and only ports that stopped being confirmed age out.

---

# Part 4 — Service detection

## 4.1 `http_probes` (modified upstream plugin)

Two handlers:

- `fqdn_endpoint.go` — position 41 on FQDN, 16 instances. Actively
  triggers scans via `OpenPortsForFQDN`, then probes.
- `ipaddr_endpoint.go` — position 42 on IPAddress, 32 instances. Reads
  prefilter results passively.

`fqdn_endpoint.go` bails early for names with no A/AAAA/CNAME record
type — three in-memory map lookups, no I/O. This is why the huge
`in-addr.arpa` tail (~70% of all FQDNs on a university target) costs
essentially nothing here.

Services are created as `ServiceWithIdentifier(addr, "tcp", port)` with a
`PortRelation` edge from the FQDN or IPAddress.

## 4.2 `protocol_probes` (new plugin)

Position 43 on IPAddress, 16 instances. Non-HTTP service detection:

- `banner_peek.go` — connect, read whatever the service volunteers
  within `PeekTimeout`.
- `classify.go` — `ClassifyPeek` returns `GuessSSH`,
  `GuessAmbiguousBanner`, or `GuessSilent` (no data).
- `recog_client.go` — Recog fingerprint matching, **embedded** via
  `runZeroInc/recog-go`. No external service. Selects fingerprint
  databases by port (`ssh_banners.xml` for SSH; SMTP/FTP/POP/IMAP/NNTP/
  telnet sets otherwise) and tries each candidate form in order.
- `banner_normalize.go` — turns a raw wire banner into the forms Recog
  can actually match. See below; this file is the difference between the
  plugin identifying products and identifying nothing.
- `certharvest.go` — TLS certificate harvesting for silent ports.
- `service.go` — Product/ProductRelease storage.

**Banner normalisation is load-bearing and non-obvious.** Recog's
fingerprints match the *field after* the protocol greeting, not the wire
banner — `imap_banners.xml` explicitly documents that `* OK ` is expected
to have been stripped before matching. So `+OK Dovecot ready.\r\n` never
matches while `SSH-2.0-OpenSSH_9.6` does, because SSH patterns are
anchored on `^SSH-` and include the protocol token.

`BannerCandidates` returns several forms in a **deliberate order**: the
full trimmed banner first (so SSH still matches), then greeting-stripped
forms (so POP/IMAP/SMTP/FTP can match), then first and last line (for
multiline FTP `220-` … `220`). That ordering is load-bearing — reversing
it breaks SSH.

Verified in production: two Dovecot identifications, one from a POP3
`+OK Dovecot ready.` banner and one from an IMAP `* OK [CAPABILITY …]`
banner. Both are forms that could not match before normalisation
existed.

**Service creation and dispatch (fixed 10-09).**

- The `tls` Service is created only after a successful TLS handshake.
  Silent non-TLS ports (RDP, databases, tcpwrapped, decoys) no longer
  become Services.
- Protocol-Probes Services are dispatched, with a `Protocol-Probes`
  source on the Service and its port edge, so Banner-URLs, Page-Links,
  Tech-Stack and JARM process them. TLS Services are dispatched after the
  certificate chain is stored, so JARM sees the `certificate` edge.
- The `PortRelation` is named `tcp_port_<n>`, as `http_probes` names it.
  The unnamed relation added a parallel IP→Service edge on SQLite and
  blanked `http_probes`' label on the shared edge on Postgres.
- Private and non-routable addresses are never banner-peeked or
  TLS-handshaked (3.3).

**Leaf certificate names (fixed 10-10).** The leaf certificate's dispatch
now carries the parsed certificate (`Meta`), the way `http_probes` does,
so TLSCert-Expansion links its CN and SAN names. Before, certificates
from non-HTTP TLS services (IMAPS, LDAPS, SMTPS, VPN portals) were stored
with no names (the old 10.5 item). These names can widen scope only
through horizontals' TLS-certificate handler, which needs the subject
organisation already in scope and does nothing under `-rigid`.

## 4.3 `enrich/techstack.go` (new)

Position 44 on Service, 16 instances. Wappalyzer fingerprinting of
already-fetched page bodies via `projectdiscovery/wappalyzergo`.

Measured accuracy against nmap ground truth: three-for-three
(`lighttpd`, `Nginx`, `Ubuntu`), with 732 of 747 services carrying at
least one product — a **98% identification rate**, not the 15% an
entity-count comparison would suggest.

**Critical modelling note.** `Product.Key()` is the product *name* alone,
so Product entities are globally deduplicated: one `Nginx` entity for the
whole estate. `ProductRelease.Key()` is the version string, likewise
global. Counting Product entities tells you how many distinct
technologies exist, **not** how many services were identified. For
per-service rates, count `product_used` edges.

The fork adds a second `product_used` edge from the **Service** to the
**ProductRelease**, so per-host versions are recoverable. Without it, a
host running nginx 1.18.0 is indistinguishable from one running 1.30.4,
because both hang off the same global `Nginx` node.

**Angular version recovery (fork addition).** wappalyzergo — at every
released version through v0.3.2 — compiles `dom` and `js` fingerprint
rules but **never evaluates them**: `GetDOMRules()` is defined and called
nowhere in the match path, and `js` rules need a JS runtime. Angular
(2+) is defined in the signature data with *only* `js` and `dom` rules,
so the library detects modern Angular **not at all** from a static
response — not merely without a version. `techstack.go` supplements this:
after the wappalyzer pass, `detectAngular` extracts the version from the
`ng-version="X.Y.Z"` DOM attribute (present in SSR/prerendered output)
with a package-level regex and, when the library did not already report
Angular, stores the product and release through the *same*
`storeProduct`/`storeRelease` path — so the rows are indistinguishable
from a native detection. Guarded by `angularSeen` so a future library
version that detects Angular statically won't double-store. Recovers
SSR'd Angular only; pure client-side-rendered Angular has no `ng-version`
in the static bytes and is out of reach without JS execution.

The same static-only ceiling applies to other SPA frameworks, and it is
**not** a bug to fix: React/Vue/Next.js/Nuxt are detected but rarely
versioned, because their versions live in the executed runtime, not the
captured bytes. Measured release coverage confirms the principle —
frameworks whose version appears in a meta tag, header, or versioned
script URL (jQuery, Astro, Gatsby) get releases; those whose version is
runtime-only (Vue.js, Next.js, Nuxt.js) get zero. WordPress *plugins*,
by contrast, version well (Yoast, Elementor, WooCommerce, etc.) because
WordPress server-renders `?ver=` script URLs, generator meta tags, and
versioned HTML comments — all static. Angular is the one framework where
a DOM attribute made the version statically recoverable, hence the
special-case handler.

**wappalyzergo v0.3.2 (bumped from v0.2.94).** Straight dependency bump;
`New`, `FingerprintWithInfo`, `FormatAppVersion`, and the `AppInfo`
struct are unchanged, so no calling code changed. The bump pulled newer
`golang.org/x/{net,crypto,text,tools}` transitively. It does **not** fix
the dead `dom` path — that gap is why the Angular handler above exists.
v0.3.x also adds `FingerprintWithRuntime` (a `Collector` seam for
browser-runtime evidence), unused here but the future hook for
JS-rendered detection.

**Product identity (fixed 10-09).** Product IDs and ProductRelease names
are lowercased (`support.ProductID`, `support.ProductReleaseName`), so
"Nginx" from Wappalyzer and "nginx" from Recog are one entity. On
Postgres the second spelling violated `entity.natural_key`'s unique
constraint and was lost. Rows written under the old mixed-case keys are
reused by the source that wrote them.

**Website and CPE.** Each Product also carries `website` and `cpe` simple
properties from the Wappalyzer fingerprint, stored the same way as
`icon`. Empty values are skipped; CPE is unset on most fingerprints.

> **Trap.** An earlier attempt used a new label, `release_used`.
> `ValidRelationship` rejected all 86 attempts silently. `serviceRels`
> permits exactly four labels out of a Service: `provider`,
> `certificate`, `terms_of_service`, `product_used` — and `product_used`
> is valid to **both** Product and ProductRelease. **Always check
> `open-asset-model/relation.go` before inventing an edge label.**
> Consumers distinguish the two by the target entity's type.

## 4.4 `jarm.go` (fixed)

Position 42 on Service, 16 instances. Ten TLS handshakes per target
produce a 62-character fingerprint of the server's TLS stack.

**The bug, and why it matters as a lesson.** `query()` fetched the FQDN
or IPAddress on the `From` side of the port relation, type-switched to
validate it — and then stored `e.Entity` (the *Service*) in the target
struct. `JARMFingerprint` needs an FQDN or IPAddress and returned
`"target must be a FQDN or IPAddress"` every time.

Result: 467 services marked processed, **zero** fingerprints, across
multiple full enumerations. The fix is `asset: a` in both switch
branches.

It was found by adding one log line to a discarded error. Three
successive theories from code reading — transformation config, a
certificate-ordering race, `hasCertificate` — were all wrong. See
Part 11.

## 4.5 Protocol string normalisation

`http_probes` wrote `Protocol: "TCP"`; `protocol_probes` wrote `"tcp"`.
Consumers (`jarm.go`, `pagelinks.go`) compared against `"TCP"` exactly,
so they silently skipped every `protocol_probes` service.

Now: all writes are lowercase `"tcp"`, and consumers use
`strings.EqualFold`. Both, deliberately — a persistent database still
holds `"TCP"` rows written before the change.

## 4.6 `api/thc.go` (new OSINT plugin)

`IP-THC` queries [ip.thc.org](https://ip.thc.org/) (unauthenticated CSV,
50k cap). Three lookups:

- FQDN / `HasSLDInScope`: subdomains of the apex, plus reverse CNAMEs.
- IPAddress: names seen on the covering IPv4 `/24`, **only** when the IP
  is in a seed-owned netblock (`support.IPInOwnedNetblock`). Cloud/CDN
  space is never queried. IPv6 is skipped.

**THC's "rDNS" endpoint is passive forward DNS, not PTR.** Each CSV row
(`apexDomain,subdomain,…,ipAddress`) means "this name was once seen
resolving to this IP". So only the names are stored. No relation in the
model describes "resolved here at some point": a `ptr_record` edge would
claim a PTR record that may not exist, and a `dns_record` edge would
present possibly stale data as a current A record, which `ips_by_domains`
would report as `forward_dns`. Each name goes through the FQDN pipeline,
which links it to the addresses it resolves to now.

Names are stored only when `IsAssetInScope > 0` (same as HackerTarget).
Out-of-scope reverse-CNAME hits are counted in the log and dropped — this
plugin is not a horizontal expander.

**Provenance.** Lookup keys get `last_monitored = 'IP-THC'`. Stored names
get a `SourceProperty` whose tag is `property_name = 'IP-THC'`,
`property_value = '70'` (confidence). Do not confuse the two. Do not scan
all of `entity_tag` for `property_value = 'IP-THC'` on a large estate;
scope the join through `fqdn_by_domains(...)`.

Rate limit: 2 s/request. HTTP 429, 401, 403, 5xx and transport errors
are not marked monitored, so the next session retries; any other status
is taken as THC's answer (4.8). Verified on a mid-sized medical-device manufacturer: hundreds of
in-scope FQDNs tagged `IP-THC` / `70` from the FQDN half alone, matching
the `IP-THC CSV kind=subdomains rows=N` log lines.

Register in `engine/plugins/load.go` (`api.NewIPTHC`). Transformations
must permit FQDN→FQDN (and IPAddress→FQDN for the RDNS half).

## 4.7 `api/alienvault.go` (new OSINT plugin)

`AlienVault` queries OTX DirectConnect passive DNS:
`GET https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns`,
header `X-OTX-API-KEY`. Source name is exactly `AlienVault` to match the
`datasources.yaml` credential entry. `HasSLDInScope`-gated, in-scope
hostnames only, 1 req/s. Position 22, shared with CertSpotter and
crt.sh, so it is a `Parallel` stage (10.1). A rejected key (401/403), an
unexpected status or an undecodable body moves on to the next key and
leaves the name unmarked (4.8). Registered first in `load.go`'s
`pluginNewFuncs`. Measured yield
on a fresh two-week window: ~5.4 names/apex — a solid contributor,
comparable to URLScan, above HackerTarget. Confirmed storing FQDNs at
confidence 70.

## 4.8 Lookup outcomes: mark only when the source answered

**The rule.** A data-source plugin marks an asset monitored
(`MarkAssetMonitored`) only when its lookup completed: the source
answered, even if the answer was empty. A failed lookup leaves the asset
unmarked, so the next session retries it instead of skipping that source
for the whole TTL. Failures include transport errors, unexpected
statuses, rate limits, a call skipped because the rate-limit wait was too
long, and bodies that do not decode.

Before 10-10 every plugin marked after every lookup. A rejected key, an
exhausted quota or a timeout looked exactly like "no results" and was
silent. That is how URLScan went dark for two weeks unnoticed (4.10).

`support/lookup.go` holds the two helpers:

- `HTTPLookupFailure(resp, err)` returns why a response is unusable, or
  `""` for a 200 with a body.
- `LogLookupFailure(log, plugin, target, reason)` logs
  `lookup failed; not marked, will retry next session` with `reason=`,
  at most one line per plugin per minute, with
  `failures_since_last_log` counting the ones folded in.

**These lines go to the engine log, not the enum logs (9.1).**

Applied to: URLScan, HackerTarget, crt.sh, CertSpotter, SubdomainCenter,
DNSDumpster, AlienVault, DNSRepo, RapidDNS, IP-THC, Prospeo, and RDAP,
WHOIS and GLEIF (4.11). Plugin specifics:

- **HackerTarget:** the "API count exceeded" notice (plain text, status
  200) is a failure. Other plain-text replies are still taken as the
  answer, since one may mean "nothing found" and retrying it would spend
  the quota.
- **CertSpotter:** pages fetched before a failed page are stored; the
  next session fetches the whole list again.
- **DNSRepo:** a non-200 or undecodable API response moves on to the next
  key and then the public page.

Not yet converted, so still marking on every lookup: BinaryEdge, Chaos,
LeakIX, SecurityTrails, VirusTotal, ZETAlytics, CommonCrawl, SiteDossier,
DNSHistory, Grep.App, Aviato.

## 4.9 `api/prospeo.go` (current Prospeo API)

FQDN pipeline, position 29, `Transforms: Identifier`. Finds work email
addresses for people at a scope domain through the current Prospeo REST
API (`https://api.prospeo.io`, header `X-KEY`):

1. `GET /account-information`: the remaining credit balance. Free.
2. `POST /search-person` with the company website filter: one credit per
   25 results.
3. Enrichment of each person found: one credit per record.

Spending is bounded per domain by two options on the `Prospeo` entry in
`datasources.yaml`:

```yaml
  - name: Prospeo
    creds:
      account:
        apikey: <key>
    options:
      max_emails_per_domain: 25   # people enriched per domain; 0 turns the plugin off
      min_remaining_credits: 0    # credits never spent
```

A domain costs at most `ceil(max/25)` search credits plus `max` enrichment
credits, and nothing is spent once the balance reaches the reserve.
Errors come back as `{"error": true, "error_code": "..."}`, mostly with
status 400. The plan's per-day search limit (50 on the free tier) shows
as HTTP 429 on `/search-person` while `/account-information` still
succeeds. That lookup is left unmarked and retried in a later session.

## 4.10 URLScan's User-Agent (`api/urlscan.go`)

URLScan requests send `User-Agent: OWASP-Amass/5
(+https://github.com/owasp-amass/amass)` and `Accept: application/json`;
every other plugin sends Amass's default Chrome User-Agent
(`internal/net/http`).

**Why.** urlscan.io answers API requests that claim to be a browser with
HTTP 429 *before it checks the key*. Nothing reaches the key's quota or
its activity log; the dashboard shows 0% usage while every lookup fails.
Found by sending the same search from inside the engine container,
adding Amass's headers one at a time: wget's own User-Agent got 200
(`X-Rate-Limit-Scope: user`); Amass's got 429.

**Consequence.** Weeks of 429s from the browser User-Agent escalated to an
IP-level block: TLS connections to urlscan.io were reset from every
client on the host. It lifted on its own within hours once URLScan was
disabled in `datasources.yaml`. If URLScan 429s again with the quota
unused, suspect request shape before quota.

## 4.11 RDAP, WHOIS and GLEIF

The same rule as 4.8, with each source's notion of "answered":

- **RDAP** (`api/rdap/`, Netblock and AutonomousSystem): openrdap's
  `ObjectDoesNotExist`, `BootstrapNoMatch`, `BootstrapNotSupported` and
  `InputError` are answers. `NoWorkingServers`, `RDAPServerError`,
  timeouts and bootstrap download failures are failures
  (`rdapLookupFailure` in `lookup.go`). Netblock RDAP has a 30-day TTL in
  production, so a failure marked as done used to hide a block's
  ownership for a month.
- **WHOIS** (`whois/fqdn_lookup.go`, domains): answered when either the
  domain's RDAP server or port-43 WHOIS answered. RDAP 404
  (`errRDAPNotFound`) and WHOIS no-match, reserved, premium, blocked and
  domain-mismatch replies are answers; `ErrDomainLimitExceed` and
  `ErrDomainDataInvalid` are failures.
- **GLEIF** (`api/gleif/`): HTTP 404 and an empty search are
  `ErrGLEIFNotFound`, an answer. Other statuses are failures. A non-200
  used to be read as a match at confidence 100. The related-organisation
  handler stores what it received but marks only when both the parent and
  children requests completed.

## 4.12 PassiveTotal — not loaded

`api.NewPassiveTotal` is commented out in `load.go`, like Hunter.io;
`passivetotal.go` stays in the tree. The plugin never sent a request:
`query()` starts with `lastid` empty and loops only `for lastid != ""`.
There is also nothing to fix it against: RiskIQ's PassiveTotal API went
to Microsoft with RiskIQ.

---

# Part 5 — Page-link provenance (`pagelinks.go`)

Position 43 on Service, 16 instances. Extracts hostnames from page bodies
already fetched by `http_probes`, **without scope filtering** (out-of-
scope names are stored too, and the engine's own scope gating keeps them
inert).

The fork adds a provenance chain answering "which page did this hostname
come from":

```
URL(page) --file--> File --contains--> URL(link) --domain--> FQDN
URL(page) --domain--> FQDN(origin)          ← the origin anchor
```

All four labels are model-declared. The **origin anchor** is essential
and easy to omit: `fqdnRels` declares no outgoing relation toward URL, so
without that edge, "what did crawling this host find?" has no traversable
entry point at all.

Design decisions:

- **Fragments stripped** — `/page`, `/page#intro`, `/page#methods`
  collapse to one URL entity. Query strings are *not* collapsed.
- **`maxLinksPerPage = 1000`** bounds URL entities per page. It is a
  safety valve against sitemaps, not a policy limit, and it applies
  **only** to URL provenance — hostname extraction is never capped.
- **Additive and failure-tolerant.** FQDN discovery is unchanged whether
  or not any provenance write succeeds.

Cost varies enormously by target: a small community college produced ~81
URL entities per crawled page; a mid-sized private university produced
~6. Budget for the former.

Verified in production on a small community college: 43 File entities,
5,100 `contains` edges,
3,375 `domain` edges, both traversal directions returning correct
results, no errors.

---

# Part 6 — Scope correctness fixes

These are subtle and they matter. Read the in-code comments too.

**`ip_netblock.go` and `whois/bgptools/netblock.go`** — both previously
registered *every* discovered netblock with the live scope tracker via a
resolution-based gate (`support.HasInScopeFQDN`: does any in-scope FQDN
resolve into this block?). Since these plugins fire on every IPAddress
the pipeline touches, and scope containment then marks every address in
an admitted range in-scope, a single in-scope name resolving into a
cloud range admitted the *entire* range — confirmed on real data as the
mechanism behind whole AWS/Azure/Google/Cloudflare `/10`–`/12`s being
scanned.

> **Superseded in 1.1 (13.4.6).** Resolution alone no longer admits a
> netblock of any size: the two-condition gate below is now logged as a
> `scope decision` and declined (`scope_vetoes: enforce`). Ownership is
> decided by the block's registration. The history below explains why the
> gate existed; keep it in mind if you ever set `scope_vetoes: observe`,
> which restores it.

**The gate now requires both conditions** (6.2): the block is IPv4 with
mask `/20` or longer (`support.PrefixEligibleForAmbientAdmit`) **and** an
in-scope FQDN resolves to the IP (`support.HasInScopeFQDN`). Genuinely
owned blocks of any size still reach scope via the ownership path (6.1),
which is not size-gated. Individual target IPs on shared infrastructure
still get scanned via provenance authorization (6.3), whether or not
their netblock is scoped.

**History, because it went wrong once.** On 09-21 (`038a978e`) the size
check was meant to be *added* to `HasInScopeFQDN`; instead it
*replaced* it, and the helper was deleted. From then on every small
block that any IP the pipeline touched fell into was admitted, including
CDN and SaaS `/24`s that out-of-scope links and CNAME targets resolve
into. The bug stayed quiet until two amplifiers landed (6.5 and 3.3).
Then it showed itself on small companies (under 200 assets) whose runs
grew to tens of thousands of names and 30k services:

1. An admitted Cloudflare, Bitly or Stripe `/24` made its RDAP
   `IPNetRecord` in scope.
2. Horizontals' registration-record handler (`processIPNetRecord`) put
   the registrant organisation in scope.
3. Horizontals' FQDN handler then added `cloudflare.com`, `bitly.com`
   and `stripe.com`, matching their WHOIS records to those organisations
   at confidence 100.
4. Subdomain OSINT ran on them (6.5), the names resolved into more small
   blocks, and Port-Prefilter scanned every in-scope IP (3.3).

`-rigid` stopped it because horizontals does nothing under it. Fixed on
10-14 (`5e026040`, PR #9) by restoring `HasInScopeFQDN` as the second
condition. Step 2 is still inferred from the code rather than seen in a
log, because that handler added assets silently; it now logs (6.6).

**`dns/ip.go`** — two changes. (1) Sweep sizing is driven by FQDN-based
scope only; coupling it to netblock membership would let a target on
shared cloud infrastructure trigger a 250-address active sweep of
unrelated hosts. (2) **Provenance authorization** (6.3): an IP that an
in-scope FQDN resolves to is individually authorized for scanning,
independent of its enclosing netblock.

**`dns/reverse.go`** — the PTR-triggered sweep was **removed**, not
fixed. Its IP-based scope check had never once succeeded, so the sweep
had never fired. The PTR-resolved hostname is a discovered output, not a
validated input, so checking scope against it would be new behaviour
rather than a preserved one.

> **Merge note.** `dns/reverse.go` is the single true textual conflict
> with the `feature/active-proxy-egress` branch, which adds a
> fail-closed guard to the same block. Take this branch's deletion —
> which also removes that branch's `PerformActiveQuery` call, the only
> place DNS would have been proxied. `dns/reverse.go` has since gained
> `attributeOwned` (6.4); keep it.
>
> **Merge note (netblock gate).** `merge/active-proxy-egress` still has
> the pre-09-21 gate: `HasInScopeFQDN` alone, any size. It has neither
> the size-only bug nor the fix. When porting, take this branch's
> `ip_netblock.go` and `whois/bgptools/netblock.go` (both conditions),
> not either half alone.

## 6.1 Owned-netblock fill (`support/owned_netblock.go`)

**This is the 10.7 design, shipped.** RDAP contact email domain ∈ seed
list → the netblock is attributed to the organisation at confidence 100
(`Owned-Netblock`). IPs in that block are synthesised and submitted so
`port_prefilter` sees them even with no hostname.

Fail-closed: missing edges, no email, or a cloud/personal mailbox →
false. This is an additional path alongside the ambiguous-path gate (6.2),
not a replacement for it. `support.IPInOwnedNetblock(ctx, session, ip)`
answers "is this IP in a seed-owned block" from the IP's `contains`
edges; THC (4.6) and PTR attribution (6.4) use it.

Prefix floor `ownedMinPrefixBits = 16` — a `/15` or larger is not
filled. **When the fill runs:** with `-active`, `AdmitOwnedNetblock` starts
a fill (in a goroutine, once per CIDR per engine process) as soon as a
block is attributed mid-run, and `FinishOwnedNetblockFills` at session end
attributes and fills any scoped block whose contacts only matched later.
The fill dispatches each synthesised IP as a new event, so the IPs pass
Position 41 themselves; the race that sank the reverted version (deciding
ownership after the IP had already passed its consumers) does not arise.

Since 1.1 the fill is **paced** to the pipeline (13.9) and addresses in
unrouted /24s are filled but not port-scanned (13.7).

Cost on a large public university: a `/16` is ~65k PTR + 65k×100 SYNs.
Closed ports fail fast; wall clock is hours, not minutes. That is
accepted when the block is ironclad-attributed. **Full fills are a
deliberate policy:** the operator wants thorough enumerations, so there is
no size cap below `/16`. Do not add one without asking.

IPs already in the backlog are not duplicated (schema + TTL). Fill does
not undo work already done on those addresses.

## 6.2 Netblock size gate plus in-scope name (`support/owned_netblock.go`, `support/database.go`)

Applies on both the `ip_netblock` and `bgptools` paths, together with
`HasInScopeFQDN` (6, above): both must hold. `PrefixEligibleForAmbientAdmit(p)`
returns true for IPv4 prefixes with mask `/20` or longer (`p.Bits() >=
ambientAdmitMinPrefixBits` = 20, and `<= 32`); IPv6 and anything wider
than a `/20` are refused. This is the **ambiguous** path — used when
there is no strong ownership signal — and it is deliberately stricter
than the fill floor (`ownedMinPrefixBits` = 16): a `/16` we cannot
attribute is 65,536 addresses of possibly-shared infrastructure, too
large to scan on a weak signal, whereas a genuinely owned `/16` still
reaches scope through the ownership path (6.1), which has no size cap.

Three admission paths now coexist, by strength of signal:

| Signal | Path | Size limit |
|---|---|---|
| RDAP contact ∈ seed (strong positive) | `AdmitOwnedNetblock` / session-end fill (6.1) | none |
| in-scope name resolves to the IP, no ownership signal | `PrefixEligibleForAmbientAdmit` **and** `HasInScopeFQDN` | ≤ /20 |
| individual IP resolved from in-scope FQDN | provenance authorization (6.3) | per-IP |

> **Superseded in 1.1 (13.4.6).** The table above describes 1.0. In 1.1
> the middle row (resolution + size) is declined, and a negative signal
> *was* shipped, on a different basis than the one below: the
> registration verdict calls a record **foreign** when it names a real,
> non-placeholder organization that is not in scope **and** has a contact
> email on a non-freemail domain that is not in scope. Redaction does not
> need detecting for that rule, because a redacted record carries no real
> organization and no usable email, so it comes out "no information", not
> foreign. The per-IP RDAP lookup (13.4.7) fetches the record early enough
> for the decision. The analysis below is still why a *redaction-based*
> negative was dropped.

A strong *negative* signal was **designed in detail and then dropped as
unbuildable** — recorded here so it is not re-proposed. The intended
three-way logic was: strong positive (contact ∈ seed → in-scope, any
size); strong negative (contact present, **not redacted**, out of scope
→ rejected, any size); ambiguous (redacted, absent, or unattributable
→ size gate). The redaction test was the crux: it existed to stop the
negative signal from wrongly rejecting a *privacy-redacted but genuinely
owned* block — distinguishing "provably someone else's" from "we can't
see who owns it."

It was dropped for two independent, verified reasons:

1. **The redaction detector could not be built.** It would have read GDPR
   markers (`REDACTED FOR PRIVACY`, RFC 9537 structures, proxy domains)
   out of the raw registration text — but `IPNetRecord.Raw` is **never
   populated** (`rdap/netblock.go` constructs the record without it; the
   stored `attrs` carries only `status: ["active"]`, no redaction
   marker). There is nothing to detect redaction *from*. Without it,
   "contact present and out of scope" cannot tell foreign from blinded,
   so a naive negative signal would reject redacted owned blocks.
2. **The signal has no data at admission time anyway.** Only ~17% of
   netblocks ever get a resolvable RDAP contact, and the `registration`
   edge the contact walk depends on is created by the RDAP plugin at
   **position 40**, while netblock admission happens at **position 4** —
   so at the moment the decision is made, the contact almost never
   exists yet. (This is also why ownership admission is a *session-end*
   operation, 6.1.)

So the shipped logic is two-way: strong positive (ownership path, any
size) + size gate with an in-scope name for everything else, with
provenance (6.3) covering
individual target IPs. Those cover the dangerous case (large ambiguous
ranges, refused by size) and the valuable case (target IPs on cloud,
authorized individually); the negative signal's marginal benefit —
refusing a *small* provably-foreign block — was not worth machinery that
couldn't run when needed. Verified on a fresh cloud-heavy target: an
8.4M-address `/9` and multiple AWS/Azure `/10`–`/12`s were recorded but
**not** scoped (a containment test showed a single scanned IP inside the
`/9` — the one provenance-authorized host — not millions).

## 6.3 Provenance-based scan authorization (`dns/ip.go`)

When an in-scope FQDN resolves to an IP, that specific IP is authorized
for scanning via `Scope().Add(ip)` — which stores an exact-match IP in
the scope's address set, so `addressInScope` returns in-scope for that
one address regardless of its netblock. This is what lets target assets
hosted on shared cloud infrastructure be scanned after the size gate
(6.2) stopped admitting their enclosing `/10`. Verified end to end:
in-scope names on AWS/GCP IPs (`api.hrpos.<seed>` → `3.170.73.x`, etc.)
get the full `open_port` → `Port-Prefilter` → `HTTP-Probes` →
`Protocol-Probes` chain via provenance alone.

Key properties, all deliberate:

- **Exact-match only.** `Scope().Add(ip)` authorizes that one address,
  never its neighbours or CIDR.
- **Does not enable fill.** Fill and the session-end sweep key off
  `Scope().Netblocks()`, never `Scope().IPAddresses()`, so a
  provenance-authorized IP cannot trigger netblock fill.
- **Storage precedes authorization.** The IPAddress asset and its
  `dns_record` edge are created before the authorization check, so an
  RFC1918 or otherwise non-scannable resolution is still *recorded* (an
  information-disclosure finding for the client) even when it should not
  be scanned.
- **Non-routable addresses are not authorised** (since 10-09):
  `support.IsNonRoutableAddress` (RFC 1918, RFC 4193, loopback,
  link-local, multicast, unspecified, `amassnet.ReservedCIDRs`) keeps them
  out of scope and out of the neighbour sweep. Port-Prefilter and
  Protocol-Probes skip them as well (3.3, 4.2).
- **A temporary `Info` log line** (`provenance scan authorization: added
  IP to scope`) is present for observability during the merge-branch
  port and should be removed once the port is verified.

## 6.4 Owned-block PTR attribution (`dns/reverse.go`)

When a PTR answer for an IP in a seed-owned netblock is an **in-scope**
name, `attributeOwned` also records:

- `IP -ptr_record-> host`, next to the existing two-hop chain
  `IP -ptr_record-> <ip>.in-addr.arpa -dns_record(PTR)-> host`. `oam_viz`
  shows it as a leaf.
- `apex -node-> host`, so `oam_subs` and domain queries list the name even
  when it has no A record. The apex handler (`dns/apex.go`) creates
  `node` edges only for names that resolved. Names that spell out the
  address (`10-1-2-3.dhcp.example.com`, checked by
  `ptrNameEmbedsAddress`) get no `node` edge, so a `/16`'s generic PTRs do
  not flood the subdomain list.

Both checks (owned block, in-scope name) must pass, so other address
space is untouched. The scope check runs first, so the ownership walk
only hits the database for IPs with an in-scope PTR name. When the PTR
data came from the database within the TTL rather than a live query,
only missing edges are created, so last-seen times keep reflecting the
last real lookup. If the apex is not known yet when the PTR answer
arrives, the `node` edge is added the next time the IP is processed.

> **Trap fixed alongside.** Horizontals' IP handler
> (`horizontals/ipaddr.go`) took the *first* `ptr_record` edge as the arpa
> name. The database lists the newest edge first, so a direct edge (this
> section, or URLScan's `page.ptr`) hid the PTR chain and stopped the
> sweep. It now follows the edge whose target ends in `.in-addr.arpa` or
> `.ip6.arpa`.

Reports are unaffected: `ips_by_domains` follows only the arpa → PTR
chain, and the tech-stack query walks neither `node` nor `ptr_record`.

## 6.5 FQDN OSINT bypass gate and runtime scope domains (`registry/osint_bypass.go`)

A FIFO gate sits on the FQDN pipeline just before the subdomain-OSINT
positions (`fqdnOSINTFirst` 20 to `fqdnOSINTLast` 40). Discovered names
skip the range and go straight to HTTP probing (`pipeline.SendData` to
the first stage after 40). That removes the head-of-line blocking at the
one-event-wide `Parallel` stages (10.1): a scope domain held for tens of
seconds in crt.sh no longer holds up DNS-resolved names behind it.

These names take the OSINT path:

- **Configured domains** (`Config().Domains()`), including the
  overlapping case (`www.example.com` alongside `example.com`), which the
  gate flags with `HasSLDInScope` because Known-FQDN does not.
- **Runtime scope domains** (since 10-09): any name Known-FQDN flagged
  with `HasSLDInScope`, i.e. apex domains added to scope during the run
  by horizontals, TLS certificate CNs or DomainRecords. Without this,
  domains found during a run got no subdomain OSINT at all.

**This is also the amplifier in 6.** Before 10-09, a wrongly admitted
domain was resolved and probed but never sent through OSINT. Now one bad
scope addition gets the full OSINT treatment. Keep scope admission
strict; this gate trusts it.

`assertOSINTBypassInvariant` panics at startup if any FQDN handler in
positions 20–40 is not on the vetted skippable allow-list, so a future
non-OSINT handler placed in the range fails loudly instead of silently
skipping discovered names.

## 6.6 Horizontals logs every scope addition

The FQDN, Organization and Location handlers log an association
rationale when they change scope:

```
[FQDN: x] is related to an asset with associative value [DomainRecord: x], which has a related
asset [...] that is in scope: matches [Organization: ...] at a confidence of N out of 100.
The following assets were added to the session scope: [...]
```

The TLS-certificate and registration-record handlers added assets
through `addToScopeAndEnqueue` without logging anything. That is why
step 2 of the 6 incident could not be seen. `addToScopeAndEnqueue` now
logs `asset added to the session scope by horizontals` with the type and
name. All of these go to the **session's enum log**, not the engine log
(9.1). To list a run's scope additions:

```bash
sudo LC_ALL=C grep -F 'added to the session scope' logs/amass/enum/<run>.log | cut -c1-500 | head
```

---

# Part 7 — Upstream defects found and fixed

## 7.1 Session semaphore deadlock (`sessions/session.go`)

`Acquire()` held the session lock across the blocking `sem.Acquire()`
call. Since `Release()` and the dynamic-resize path both need that lock,
one goroutine blocked on a full semaphore starved everything else
permanently. Confirmed by goroutine dump: one goroutine in the call
holding the lock, hundreds queued behind `Lock()`.

Fix: lock, copy the channel reference, unlock, then operate. Applied to
`Acquire`, `Release`, and the new `InUse`/`Cap`.

## 7.2 BGP.Tools unbounded read (`whois/bgptools/plugin.go`)

`whois()` applied its 10-second context timeout to the **dial only**.
`io.ReadAll(conn)` is not context-aware and had no deadline, so a server
that accepted the connection and then went silent blocked forever — while
holding the `netblock` mutex that every uncached IP must pass through, at
position 2 of the IPAddress pipeline.

Observed in production: one goroutine in `io.ReadAll`, two others waiting
on the mutex for 12 minutes, whole engine silent, nothing logged (the
error path only runs when the function returns).

Fix: `conn.SetDeadline(ctx.Deadline())` after the dial, reusing the
existing budget.

## 7.3 BGP.Tools mutex serialisation ("Stage 1")

The same mutex was held across the network call, serialising every novel
netblock lookup engine-wide. Measured: a metronomic **11 netblocks per
minute** — one every 5.45 s — meaning the mutex was occupied ~100% of the
time, against a rate limiter permitting 60/minute.

Fix: release the mutex around `query()`, re-acquire, and re-check the
CIDRanger on re-entry (so a sibling that resolved it meanwhile
short-circuits). Up to `MinHandlerInstances` (4) concurrent queries may
now overlap — bounded and cheap.

Measured after: peak 36/minute, median 8, with idle gaps — demand-driven
rather than throttled, and **zero** WHOIS errors. A planned "Stage 2"
(bulk `begin`/`end` batching) was **dropped**: the limiter was never
reached, so batching would have delivered nothing.

## 7.4 Stranded backlog leases (`registry/pipelines.go`) — FIXED

**Symptom.** Dashboard `FQDN leased` stuck at a constant (observed 125)
for tens of minutes, pipeline workers idle in `processStageData`,
`queue = 0`, NetSem/ScanSem 0. Session-end hook can still finish
(`end-work DONE`) while enum waits forever for
`WorkItemsCompleted == WorkItemsTotal`.

**Root cause.** `sendElementOnExit` used a non-blocking send into
`dispatcher.cchan` (buf 1000). When that channel was full, the completed
element was **dropped**: no `Ack`. Combined with `SetLeaseTTL(0)`
(deliberate — a 90 s WHOIS/HTTP handler must not be reclaimed mid-flight)
and `pumpOnce` skipping when `Queued == 0`, those rows stay leased until
the session is destroyed.

**TTL was not changed.** `SetLeaseTTL(0)` stays.

**Fix.** If the send cannot happen, Ack the backlog row immediately. The
pipeline has already finished that element. A later `completedCallback`
Ack is a no-op. Handler panics are recovered and Ack'd the same way.

**Enum safety net.** After the session-end hook reports done, if WorkItems
are still not idle for 2 minutes, enum exits anyway and logs
`stranded leases`. Do not wait forever.

**Do not** Ack every leased row at hook end. That would mark in-flight
owned-fill / sweep IPs done and let enum DELETE the session while they
run.

`ClaimNext` (`backlogdb/backlog.go`) also had a `ttl` variable shadowed
inside the claim; removed 10-11. It never changed behaviour: with
`SetLeaseTTL(0)` the claim selects queued rows only and `lease_until` is
never read. `TestClaimNextZeroTTLNeverReclaims` pins both modes.

---

## 7.5 crt.sh mislabelled as HackerTarget (`api/crtsh.go`)

Upstream `crtsh.go` set `source.Name = "HackerTarget"` — hackertarget.go's
own source name (a copy-paste slip; the adjacent `Confidence` was
deliberately edited to 100 while the name line was not). Because
`et.Source.Name` is what `MarkAssetMonitored` writes as `last_monitored`
and what `StoreFQDNsWithSource` writes as the `SourceProperty`, crt.sh
(position 22) and HackerTarget (position 25) shared a single TTL slot:
whichever ran first marked it, the other skipped, and a *failed* crt.sh
query still burned the slot for both because `check()` marks regardless
of query outcome. Measured 153:1 in crt.sh's favour, so HackerTarget was
effectively dark and its findings were filed under the wrong source —
which also invalidated any historical source-value comparison that used
the `HackerTarget` tag (the two are distinguishable in old data only by
confidence: crt.sh = 100, HackerTarget = 80). Fixed to `source.Name =
"crt.sh"`; the two now have independent TTL slots and attribution. Since
10-10 a failed crt.sh query no longer marks anything either (4.8).

## 7.6 DNSHistory / SiteDossier unbounded page loops (`scrape/`)

Both scrapers paginate `for i := 1; i < 20` and broke only on
`err != nil || resp.Body == ""` — a condition that never fires against a
real web server (an error page still has a body) and never inspected
`resp.StatusCode`. So a 403 (or any block) ran all 19 pages, burning 19
rate-limiter tokens per seed for zero results, and did so *invisibly*
because the source still got marked monitored. This throttled the whole
FQDN pipeline to ~1.6 seeds/min (30 tokens/min ÷ 19). Root cause of the
block itself: these are small free services fronted by Cloudflare, and
the fleet's cumulative traffic — plus, historically, the scope leak in 6
scanning Cloudflare-adjacent ranges — dropped the engine IPs' reputation
until Cloudflare returned 403. Fixed: break on `err != nil || resp ==
nil || StatusCode outside 2xx`, and additionally break when a page
scrapes zero names (blocked, empty, or past the end). A blocked source
now costs one request, not nineteen, and fails visibly. Does not unban a
blocked IP — that needs the scanning to stop and reputation to recover.

## 7.7 DNS lookups retried 10 times (`support/resolvers.go`)

`PerformQuery` retried a failed lookup up to 10 times. A usable answer or
NXDOMAIN returns on the first reply anyway; only timeouts, refusals and
useless responses used the extra attempts. Now 6 (`bc5297d1`).
`ErrFailedMaxDNSAttempts` is what callers see when they run out.

## 7.8 Byte-order marks broke `go test -cover`

Four files (`plugins/load.go`, `api/alienvault.go`, `support/org/org.go`,
`support/org/find.go`) began with a UTF-8 byte-order mark, and nine were
not gofmt-clean. No runtime effect, but `go test -cover ./engine/plugins/`
failed to build. Fixed 10-11. Uploads through the GitHub web UI are the
likely source; check new files with `head -c3 file | xxd`.


# Part 8 — Dashboard and API additions

`engine/api/server/v1/handlers.go` adds:

- **`GET /sessions/{token}/backlog`** — `BacklogResponse` with per-asset
  `BacklogBucket{asset_type, waiting, leased, queue, processed}`, plus
  `active_connections`, `max_connections` (NetSem), `active_scan_conns`,
  `max_scan_conns` (ScanSem), `prefilter_scanned`, `prefilter_open`.
- **`GET /sessions/{token}/end-work`** — session-end hook phase
  (`idle-wait` / `listing` / `requeue` / `drain` / `done`), candidate
  count, requeued count. The dashboard `end-work` row is this, not a
  pipeline bucket. A large `queue` during `requeue` is
  `ListDone(IPAddress)` size, **not** 6k leased jobs.
- **`GET /handler-stats`** — `HandlerStatsResponse`, per-handler average
  duration from InfluxDB.

`internal/net/network.go` adds `Semaphore.InUse()` and `Cap()`;
`engine/types/sessions.go` extends the `SessionSemaphone` interface and
adds `ScanSem()`.

> **`/handler-stats` has never returned data.** The write side is
> upstream (`registry/pipelines.go` `init()` calls
> `influxdb3.NewFromEnv()`), but no `INFLUX_HOST`/`INFLUX_TOKEN` is set
> and there is no InfluxDB in the compose stack, so `influxClient` is nil
> and nothing is ever written. This was a deliberate decision — the
> telemetry would add a production dependency for development-only value.
> The code is inert, not broken.

`dashboard.py` is a local operator tool, not part of the repo.

---

# Part 9 — Operational knowledge

None of this is in the code. All of it was learned the hard way.

## 9.1 Logging — the single most valuable thing to get right

Amass's `slog` output does **not** go to `docker logs engine`.
`selectLogger()` tries syslog before falling back to stdout, and the
compose stack has a syslog-ng container.

Messages land in **`./logs/amass/engine/<date>-amass-engine.log`** on the
host.

**The `logs/` directory must be world-writable.** syslog-ng runs as
UID/GID 911; a fresh checkout gives `logs/` mode 775 owned by the host
user, so syslog-ng cannot create its directory tree and **every log line
is silently discarded**. Three layers of silence: UDP `net.Dial` never
fails, syslog-ng starts cleanly, and the destination can't be created.

```
chmod 777 ./logs      # BEFORE docker compose up
```

Add this to any environment-restore script. It is not a file, so it will
not come back from a backup.

Verify: an `amass/` subdirectory owned by 911 appears under `logs/`
within seconds of the engine starting.

Timestamps are UTC (`TZ=Etc/UTC` on the syslog container), matching the
database.

**Two kinds of log file, and which lines go where:**

| File | What it holds |
|---|---|
| `logs/amass/engine/<date>-amass-engine.log` | Everything a plugin logs through `r.Log()` (its registry logger): `Plugin started`, `lookup failed; not marked…` (4.8), plugin warnings. One file per day across all sessions. |
| `logs/amass/enum/<date>-enum-<id>.log` | Everything logged through `e.Session.Log()`: relationships discovered, horizontals scope additions (6.6), sweep and session-end lines. One file per run. |

Lines logged through a session logger carry a `session=<uuid>` field;
lines from a plugin's registry logger (`IP-THC CSV`, `lookup failed; not
marked…`, `Plugin started`) do not, so filter those by time instead. On a
shared engine log, always filter by session ID, not by `find -mmin`:
`-mmin` selects whole files, and the engine file holds every session of
the day.

Looking for a plugin's failures in an enum log finds nothing, which looks
like success. Search the engine log for those, and only the recent days'
files: they are tens of MB each.

Noise filter — the healthcheck and dashboard polling dominate:

```
grep -v "path=/api/v1" logs/amass/engine/*.log | grep -iv "\[INFO\]" | tail -40
```

## 9.2 pprof is already enabled

`engine/engine.go:34` runs `http.ListenAndServe("127.0.0.1:6060", nil)`
with `net/http/pprof` imported. From the host:

```
sudo docker exec engine wget -qO- 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=1' | head -40
sudo docker exec engine wget -qO- 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=2' | grep -c "minutes\]:"
sudo docker exec engine wget -qO- 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30' > /tmp/cpu.pprof
```

This has resolved more problems on this project than any other tool.

## 9.2.2 Startup build-info banner (`engine/engine.go`)

`NewEngine` now logs one line at boot — `engine build info` — via
`runtime/debug.ReadBuildInfo()`, reporting the Amass build revision
(`vcs.revision`, when `.git` is in the build context) and the compiled-in
versions of key deps (`wappalyzergo`, `resolve`, `asset-db`,
`open-asset-model`). It reads what is actually baked into the binary, so
it cannot drift from `go.mod`. This is the at-a-glance answer to "is this
running engine the code and dependencies I think it is?" — a question
that cost real time repeatedly before it existed. If `vcs.revision` is
absent, the Docker build context lacks `.git`; the dep versions are
always present. Add a module path to the `depVersions` slice to surface
another.

Wrap pprof `wget` in `timeout 8` and `-T 4`. A wedged completion path
can make even `:6060` slow; an un-timeout'd `docker compose exec` blocks
the rest of a diagnostic paste.

## 9.2.1 Session-end hook

`engine/engine.go` registers a shutdown hook:

1. `FinishOwnedNetblockFills` — synthesise IPs in seed-attributed blocks.
2. `SweepMissedIPs` — `ListDone` IPs with `open_port` and no
   `Protocol-Probes` mark, `ResubmitEvent` up to `sweepMaxResubmit`
   (500). Session-local.

Enum must stay up until the hook reports done (`EndWorkDone`). First-pass
idle (or the 30-minute no-progress timer) *starts* the hook; it is not
session completion. Duplicate log lines on enum stdout (`First pass
idle…` twice) are stdout + `color.Error`, not two hooks.

**The hook runs only through `RunEndWork`** (`POST
/sessions/{id}/end-work`), and only the first call per session runs it;
later calls return at once. Until 10-09 `CancelSession` (TerminateSession,
CLI Ctrl-C) and `Engine.Shutdown` also ran it before `Kill()`. So
stopping a run *started* more scanning and could block for hours, and
engine shutdown ran it twice, the second time after the dispatcher had
stopped. The sweep and the owned-netblock re-walk also stop early when the
session is killed.

**The sweep's scope** includes the session scope's runtime domains as well
as the configured ones (since 10-09). Otherwise the IPs of domains added
during the run were never swept. The configured list is kept because the
scope stores registered domains only, not configured subdomains. Under
`-rigid` there are no runtime additions, so nothing changes there.

`ResubmitEvent` now has callers. The backlog is per-session SQLite;
another engine's session cannot see these rows.

## 9.3 `compose.yaml` requirements

```yaml
  engine:
    ulimits:
      nofile:
        soft: 8192
        hard: 8192
```

Binds at container creation — `docker compose up -d --force-recreate engine`,
not `restart`. Verify with `docker exec engine sh -c 'ulimit -n'`.

## 9.4 `config.yaml`

`ports:` is currently the nmap top-100 by frequency. It was reduced from
top-1000 during the file-descriptor incident and kept there because
service detection is opportunistic.

`transformations:` gates every plugin. `default_transform_values.ttl` is
1440 minutes (24 h). Note that on a **weekly** re-enumeration cadence,
every 24-hour TTL has always expired, so the persistent caches never fire
— everything is re-queried. Adding e.g. `IPAddress->Netblock: {ttl: 43200}`
would change that.

An explicit `IPAddress->Port-Prefilter` transformation is no longer
needed: Port-Prefilter follows `IPAddress->Service` (3.3). It is harmless
to keep.

## 9.5 pgBouncer (production)

The fleet runs 30–50 instances × 4 connections = 120–200 client
connections behind pgBouncer. Requirements, in priority order:

1. `pool_mode = transaction` (session mode gives no benefit)
2. pgBouncer **≥ 1.21** with `max_prepared_statements > 0` — pgx v5 uses
   protocol-level prepared statements and the DSN hardcodes
   `statement_cache_capacity=256`. Below 1.21 this fails **only under
   load**, never in testing.
3. `track_extra_parameters = statement_timeout` — **not**
   `ignore_startup_parameters`, which accepts the connection and then
   silently discards the setting.
4. `default_pool_size` ~20, `max_client_conn` ≥ 500,
   `server_reset_query_always = 0`.

Test with `pgbench -M prepared -c 50`.

## 9.6 `datasources.yaml`

- **Uncomment by deleting `#`, never by replacing it with a space.** A
  block shifted one column no longer lines up with its neighbours, and the
  file stops parsing (`error unmarshalling datasources YAML: yaml: line
  N: …`). The enumeration then exits 1 with no message (9.7). Check a file
  before using it:
  ```bash
  python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1])); print("OK")' config/datasources.yaml
  ```
- Names match plugins case-insensitively (`GetDataSourceConfig`), but an
  entry no loaded plugin reads is ignored silently.
- A plugin with an expired key keeps sending a failing request for every
  scope domain. Comment the entry out; with no credentials the plugin
  returns before sending anything.
- Turning a source off in `datasources.yaml` takes effect at the next
  enumeration, with no engine restart: the enum client reads the file and
  sends it to the engine with each new session.

## 9.7 `enum -silent` discards error messages

`-silent` points both `color.Output` and `color.Error` at `io.Discard`
(`internal/enum/cli.go`). Every `oam_enum` failure therefore exits 1 with
nothing printed: config load errors, engine session failures, a bad
`-d`. To see the reason, run the same command without `-silent`:

```bash
sudo docker compose run --rm -T enum -active -d example.com
```

`enum-companies.py` stops the queue on any non-zero exit from `oam_enum`.
It prints that command and the remaining company ids, so a broken config
cannot burn through the whole queue.

---

# Part 10 — Known issues and traps

## 10.1 `Parallel` stages serialise events (upstream)

Positions 22 (CertSpotter, crt.sh — FQDN pipeline; note crt.sh's
source-name fix in 7.5 gives it and HackerTarget independent TTL slots,
unrelated to this serialisation issue) and 25
(SubdomainCenter, HackerTarget, DNSDumpster, URLScan, CommonCrawl,
**IP-THC FQDN**) have multiple handlers, so they become `Parallel`
stages. `Parallel` handles **one event at a time** and ignores
`MaxInstances` — those plugins declare 16 and get 1. IP-THC's 2 s/request
pacing therefore serialises the whole FQDN position-25 event, not just
THC. The IP-THC **IP** handler is alone at IPAddress position 22 and
keeps its `DynamicPool` of 16.

Observed on a 126-domain target: FQDN throughput fell to **3.4
events/minute** with the engine at 18% CPU and 516 goroutines blocked at
`pool.go:117` holding tokens, then abruptly recovered to **285
events/minute**. That 84× swing indicates one long-blocking handler
freezing the stage, amplified by the serialisation.

Also note `EventDataElement.Clone()` returns the same pointer, so
`Parallel`'s documented "copy" doesn't happen and
`ede.Error = multierror.Append(...)` is a live data race at these
positions — pre-existing, independent of any fix.

A token-pooled `Parallel` variant would fix the throughput issue. The
safety case is strong (different events are different
`EventDataElement`s; `DynamicPool` already runs handlers concurrently
across events everywhere else), but it is an upstream change.

**Mitigated for discovered names** by the OSINT bypass gate (6.5): only
configured and runtime scope domains enter positions 20–40, so the
serialised stages no longer hold up the bulk of the FQDN traffic.
AlienVault is also at position 22 (Appendix A).

## 10.2 `protocol_probes` — FIXED (was: never produced a service)

**Resolved.** Kept here because the failure lasted across five client
organizations and every enumeration, and because the way it was finally
found is the most transferable lesson in this document.

**Symptom.** Zero non-`web-service` types, ever. Ruled out by
investigation and all wrong: plugin loading, transformation config, Recog
infrastructure (it is embedded, no external dependency), `ClassifyPeek`
logic, and connection timeouts.

**Root cause — service creation.** `findExistingServiceByUniqueID` in
`certharvest.go` separated two conditions that every other
`FindEntitiesByContent` caller in the codebase keeps together:

```go
if err != nil { return nil, err }      // WRONG
if len(found) == 0 { return nil, nil }
```

`asset-db` signals "no match" by returning `errors.New("zero entities
found")`, not an empty slice. So a lookup for a genuinely new host:port
returned that error to `FindOrCreateService`, which aborted **before
reaching the branch that creates the Service**. Every new non-HTTP
service was rejected at the moment it was about to be created. The fix
is the combined test used everywhere else:

```go
if err != nil || len(found) == 0 { return nil, nil }
```

Measured: 1,391 `failed to store the Service asset` warnings in a single
day before; **zero** after, with `tls`, `unknown-banner` and `ssh`
services all appearing for the first time.

**Root cause — product identification.** Fixing service creation exposed
a second, independent failure: services were created but no Product or
ProductRelease rows followed. Recog was being fed raw wire banners. See
Part 4.2 — `banner_normalize.go` resolves it, and Dovecot is now
identified from both POP3 and IMAP greetings.

**Known remaining limit, not a defect.** Recog has no fingerprint for
every product. A `CompleteFTP` host self-disclosing `22.2.2` on both port
21 and port 22 is correctly normalised and correctly unmatched. The raw
banner is still stored in `service.attrs->>'output'`, so the version is
recoverable downstream. To build a work list of what Recog misses on real
estates:

```sql
SELECT s.service_type, s.attrs->>'output' AS banner, count(*) AS services
FROM entity se
JOIN entity_type_lu sl ON sl.id = se.etype_id AND sl.name = 'service'
JOIN service s ON s.id = se.row_id
WHERE s.attrs->>'output' IS NOT NULL AND s.attrs->>'output' <> ''
  AND NOT EXISTS (SELECT 1 FROM edge pu WHERE pu.from_entity_id = se.entity_id
                    AND pu.label = 'product_used')
GROUP BY 1,2 ORDER BY 3 DESC;
```

**How it was found.** Five runs of inference produced four wrong
theories. The answer came from a single log line added to a discarded
error — which had been sitting in the code, logging the exact cause,
unread, because the count of a *different* warning was being checked. See
Part 11.3.

## 10.3 Decoy detection fires too late to help

On the state university above, both WAF decoys were flagged correctly (59 open
ports) — but `HTTP-Probes` had marked them monitored **before**
`Port-Prefilter` finished scanning, so the flag arrived after the
consumer had given up. Same 13% race as 10.2.

`DecoyTimeBudget` (90 s) is also effectively inert with a 100-port list,
and `LikelyDecoyThreshold` (50) is an absolute count calibrated when the
list was top-1000 — where 50 meant 5%; it now means >50%.

Nothing logs when `IsLikelyDecoy` trips. **Adding one log line there is
the highest-value observability change outstanding.**

## 10.4 Cross-pipeline race (present; Protocol-Probes miss mitigated)

**The race itself remains.** Roughly 13% of IPs reach `http_probes`
before `port_prefilter` has stored their ports, because an IP can arrive
via the FQDN pipeline before its own IPAddress event passes Position 41.
The share is biased toward high-fan-in CDN and WAF addresses. Not fixed
in-pipeline: active triggering from `fqdn_endpoint` previously caused
handler-slot saturation.

**HTTP-Probes marking — FIXED.** `http_probes` used to call
`MarkAssetMonitored` even when it had no ports to probe, claiming work it
had not done and suppressing the asset for the full 1440-minute TTL.
`query()` in both `ipaddr_endpoint.go` and `fqdn_endpoint.go` now returns
`([]*support.Finding, bool)`, and `check()` marks only when the flag is
true. **The flag is not derivable from the findings slice** — "had ports,
nothing answered" and "had no ports to try" both yield zero findings and
need opposite treatment.

**Protocol-Probes miss — mitigated at session end.** IPs that hit
position 43 with an empty port list, or that were scanned only from the
FQDN pipeline, get a `Protocol-Probes` mark never. `SweepMissedIPs`
lists Done IPs with `open_port` and no mark inside the transform TTL,
gates on seed-scoped FQDNs, and `ResubmitEvent`s them (cap 500).

On Postgres the sweep uses one batch query per chunk of Done IPs
(`sweep_query.go`). It starts from each Done IP and checks the
`open_port` and `last_monitored` tags, then looks for an incoming
`dns_record` edge from an FQDN under a seed domain. Every step is an index
probe keyed by that IP, so the cost follows the number of Done IPs, not
the size of the database. IDs go in chunks of `missListChunk` (5,000),
each statement well inside asset-db's 60 s `statement_timeout`, and the
loop stops at the requeue cap.

The first version joined seed domains to `fqdn` with
`reverse_fqdn LIKE reverse(domain) || '.%'`. A pattern built from a column
cannot use the index inside a join, so it read the whole `fqdn` table,
timed out on large databases, and the sweep fell back to the old serial
walk. That walk calls `ResolvingFQDNs` per Done IP: slow (minutes) on
CloudFront-scale fan-in, and it contends with the asset-db writer. It is
still the fallback, logged as `batch miss-list query failed; falling back
to per-IP walk`. Confirmed on a large university's end-work with no
fallback. Dashboard `requeue queue` = candidate count, not leased work.
Do not confuse it with 7.4 stranded FQDN leases.

Cost of the HTTP-Probes change: assets with genuinely no open ports are
re-examined each run rather than suppressed. That is a database read, not
a network probe — `port_prefilter` guards the scan separately by TTL.

## 10.7 Netblock admission by registration contact — SHIPPED (was reverted)

The in-pipeline version was reverted because admission happened after
Position 41 and nothing put those IPs back. **Do not put the gate back
on the IPAddress pipeline.** Session-end fill is the working shape.
See Part 6.1.

What remains true from the investigation:

- The ownership test (RDAP contact email domain ∈ seed list, exact
  registered-domain match, fail-closed on cloud/personal mailboxes) is
  the right predicate. It admitted campus blocks and rejected
  AWS/Azure/Google/Cloudflare/Akamai on real data.
- `ResubmitEvent` is no longer unused — `SweepMissedIPs` and owned-fill
  call it.
- Prefixes broader than `/16` are not filled.

The general lesson stands: *a decision made after an asset has passed
its consumer has no effect unless something re-examines it.* Session-end
is that re-examination, not a mid-run scope mutation.

## 10.5 Dead-ish code and latent hazards

- `Clone()` returning the same pointer (10.1).
- `amasshttp.TLSConn` and `amasshttp.Crawl` — both dial directly, zero
  callers. Shaped exactly like things that must be proxied post-merge.
- `Clients().Crawl` — constructed, never used.
- `api/passivetotal.go`: never sends a request (4.12); not loaded.
- `ip_netblock.go` still fires on every IPAddress the pipeline touches,
  including IPs only out-of-scope names resolve to. That is harmless only
  because admission needs an in-scope name (6.2). Any future admission
  path must keep a scope signal; size alone is not one (6).
- (Fixed in 1.1, 13.4.4: horizontals' `processIPNetRecord` used to put
  the registrant organisation of any in-scope netblock into scope, so a
  target hosted on a provider block pulled the provider in. An in-scope
  record now expands its registrant only when a contact email is on a seed
  domain.)
- (Fixed 10-10: Protocol-Probes leaf certificates were dispatched without
  the parsed certificate, so their SANs were discarded. See 4.2.)

## 10.6 Active-egress gaps (pre-merge) — RESOLVED in 1.1

All three gaps below were closed by the 1.1 port (13.1): every active path
takes its dialer or HTTP client from `support.ActiveDialer` /
`support.ActiveHTTPClient`, and the nil-means-direct fallbacks were
removed, so a missing dialer fails closed. The text is kept as history.

For the pending `feature/active-proxy-egress` merge, five target-touching
egress paths exist. Two are already handled by that branch
(`JARMFingerprint`, `Clients().Probe`). Three need work:

- `scanPorts` — `fqdn_endpoint.go` passes a literal `nil`, and
  `scanPorts` responds to nil by substituting a **direct dialer**. A grep
  for `selectDialer` finds two call sites and misses this one.
- `PeekBanner`, `dialAndGetCertChain` — have seams, must be wired.

**The `nil` → direct-dial default is the real hazard**, in all three
places. It converts a missing integration into silent direct traffic. It
should fail closed.

---

# Part 11 — Maintenance methodology

This project's history is a case study in how to be wrong. The
techniques below are the ones that produced correct answers.

## 11.1 Verify against real source, always

Clone the actual dependency and read it. This project has caught, by
doing so: wrong JSON keys, wrong SQL column names, an invented edge label
rejected by the model, a wrong belief about GORM, and a wrong belief
about which timestamp column a filter uses. Every one would have shipped
otherwise.

## 11.2 Reasoning from code reading is unreliable here

Four separate problems were misdiagnosed by reading code and then
resolved instantly by a measurement:

| Problem | Wrong theories | What actually found it |
|---|---|---|
| JARM producing nothing | 3 | one log line on a discarded error |
| Engine-wide silence | FD exhaustion | goroutine dump |
| Netblock discovery slow | rate limiting | per-minute timestamp histogram |
| FQDN pipeline stalled | 4 | goroutine dump + CPU profile |
| `protocol_probes` silent | 4 | a log line already present but never counted |
| Netblock admission inert | 3 | timestamp comparison in `entity_tag` |
| FQDN leased stuck, enum never exits | 2 | pprof: idle `processStageData` + dropped `sendElementOnExit` |
| Small companies grow to 30k services | 1 (recent amplifiers alone) | scope-addition rationale lines in the enum logs, then `git log -S` on the gate |
| URLScan 429 at 0% quota | key, quota | the same request from inside the container, adding Amass's headers one at a time |
| Enumeration exits 1 silently | — | rerunning without `-silent` (9.7) |

Two of those deserve emphasis. The `protocol_probes` cause was being
logged 1,391 times a day, in a warning nobody had grepped for — the
count of a *different* warning had been checked instead, and it was zero.
**When adding a log line to diagnose something, grep for every warning
that code path can emit, not just the one you expect.**

And the schema is not guessable. Column names were wrong on first attempt
for `organization` (`org_name`), `file` (`file_url`, `basename`,
`file_type`), `url` (`raw_url`), and `netblock` (`natural_key` lives on
`entity`, not the per-type table). `\d <table>` before writing a query
against an unfamiliar table costs seconds and has been wrong three times
in one session without it.

**Prefer a measurement over an inference.** The tools are already
installed.

## 11.3 Silent error paths are the enemy

Three defects hid for weeks behind discarded errors. The pattern to watch
for is `if err != nil { return }` on a network or storage call in a
plugin. Every one added since has a log line, and each has paid for
itself.

The same goes for marking: a lookup that marks itself done on failure is a
discarded error with a 24-hour (or 30-day) sentence attached. New
data-source plugins follow 4.8. Scope changes are the same: any code path
that calls `Scope().Add` should log what it added (6.6).

## 11.4 Useful SQL

```sql
-- What ran, when, and for how long (the single best debugging query)
SELECT property_value AS source, count(*) AS assets,
       min(updated_at) AS first, max(updated_at) AS last,
       round(extract(epoch FROM max(updated_at)-min(updated_at))/60) AS active_minutes
FROM entity_tag WHERE property_name = 'last_monitored'
GROUP BY 1 ORDER BY 2 DESC;

-- Entity totals
SELECT lu.name, count(*) FROM entity e
JOIN entity_type_lu lu ON lu.id = e.etype_id GROUP BY 1 ORDER BY 2 DESC;

-- Prefilter throughput
SELECT count(*) AS scanned,
       round(count(*)/nullif(extract(epoch FROM max(updated_at)-min(updated_at)),0),2) AS per_sec
FROM entity_tag WHERE property_name='last_monitored' AND property_value='Port-Prefilter';

-- Open ports found
SELECT property_value::int AS port, count(*) AS ips
FROM entity_tag WHERE property_name='open_port' GROUP BY 1 ORDER BY 2 DESC;

-- Service identification rate (NOT entity counts - see 4.3)
SELECT (SELECT count(*) FROM entity e JOIN entity_type_lu l
          ON l.id=e.etype_id AND l.name='service') AS services,
       (SELECT count(DISTINCT from_entity_id) FROM edge
          WHERE label='product_used') AS services_with_product;

-- Which sources found which FQDNs (note: DNS records provenance on EDGES,
-- API plugins on ENTITIES - you need both queries for a full picture)
SELECT t.property_name AS source, count(DISTINCT e.entity_id) AS fqdns
FROM entity_tag t JOIN entity e ON e.entity_id = t.entity_id
JOIN entity_type_lu lu ON lu.id=e.etype_id AND lu.name='fqdn'
WHERE t.property_name <> 'last_monitored' GROUP BY 1 ORDER BY 2 DESC;

-- On a production-sized database, write queries that only use indexed
-- equality lookups, and set a timeout (SET statement_timeout = '60s').
-- A range test such as record_cidr >>= block cannot use an index and
-- ran past 10 minutes; enumerate the candidate supernets instead:
--   SELECT ... FROM (SELECT set_masklen('203.17.34.0/24'::cidr, n) AS super
--                    FROM generate_series(8, 24) n) s
--   JOIN public.ipnetrecord r ON r.record_cidr = s.super;
-- ipnetrecord.handle and record_cidr are UNIQUE; entity (table_name,
-- row_id) and edge (from_entity_id) / (to_entity_id) are indexed.

-- IP-THC: scope the join. Do not seq-scan entity_tag.property_value.
SELECT count(*) FROM fqdn_by_domains(current_setting('my.domains', true)) f
JOIN entity e ON e.etype_id = 7 AND e.row_id = f.id
JOIN entity_tag t ON t.entity_id = e.entity_id
WHERE t.property_name = 'IP-THC';
```

## 11.5 Build and test constraints

`go.mod` declares `go 1.26.0`, inherited from upstream. This is the
module's own directive, not a dependency — no pinning will move it, and
the toolchain auto-download fetches from `proxy.golang.org`. `gofmt`
works regardless.

Where logic can be isolated, extract it into a standalone test package
and run with `-race`. This has caught real bugs, including one in a test
assumption itself.

## 11.6 Do not compare throughput across targets

Prefilter IPs/sec varied 1.90 → 4.01 → 0.96 across targets for reasons
having nothing to do with the code — it measures how fast IPs arrive at
position 41, which depends on the target's DNS, netblock structure, and
filtering posture. Only compare the **same target across consecutive
runs** with one variable changed.

---

# Appendix A — Pipeline position map

| Pipeline | Pos | Handler | Instances | Stage type |
|---|---|---|---|---|
| IPAddress | 2 | BGP.Tools netblock | 4 | FIFO/Pool |
| IPAddress | 4 | IP-Netblock (waits up to 30 s for the BGP prefix; not for unrouted /24s, 13.7) | — | — |
| IPAddress | 5 | **RDAP per-IP** (1.1, 13.4.7) | 4 | DynamicPool |
| IPAddress | 8 | DNS-Reverse | — | — |
| IPAddress | 10 | Horizontals IP | — | — |
| IPAddress | 22 | **IP-THC IP** | 16 | DynamicPool |
| IPAddress | 41 | **port_prefilter** | 32 | DynamicPool |
| IPAddress | 42 | http_probes ipaddr | 32 | DynamicPool |
| IPAddress | 43 | **protocol_probes** | 16 | DynamicPool |
| FQDN | <20 | **OSINT bypass gate** | 1 | FIFO |
| FQDN | 22 | **AlienVault**, CertSpotter, crt.sh | *1* | **Parallel** |
| FQDN | 25 | SubdomainCenter, HackerTarget, DNSDumpster, URLScan, CommonCrawl, **IP-THC FQDN** | *1* | **Parallel** |
| FQDN | 29 | **Prospeo** | 16 | DynamicPool |
| FQDN | 41 | http_probes fqdn | 16 | DynamicPool |
| Service | 10 | banner_url | 16 | DynamicPool |
| Service | 42 | **jarm** | 16 | DynamicPool |
| Service | 43 | **pagelinks** | 16 | DynamicPool |
| Service | 44 | **techstack** | 16 | DynamicPool |

Bold = added or substantially modified by this fork. Italic instance
counts = declared but ignored because the position is shared. **Exclusive
handlers need a unique position per event type**: two at the same
position make the plugin's `Start` fail and the engine never becomes
healthy (that happened once in 1.1, 13.4.7). `engine/plugins/load_test.go`
starts every plugin against a real registry and fails on such a
conflict; run it after adding a handler. The bypass
gate sends discovered names from before 20 straight to the first stage
after 40 (6.5).

# Appendix B — Constants quick reference

| Constant | Value | File |
|---|---|---|
| `maxConcurrentPortsPerIP` | 100 | `support/portscan.go` |
| `PortPrefilterScanTimeout` | 2 s | `support/portscan.go` |
| `LikelyDecoyThreshold` | 50 | `support/portpriority.go` |
| `DecoyTimeBudget` | 90 s | `support/portpriority.go` |
| `maxLinksPerPage` | 1000 | `pagelinks.go` |
| `MinHandlerInstances` | 4 | `support/support.go` |
| `MidHandlerInstances` | 16 | `support/support.go` |
| `HighHandlerInstances` | 32 | `support/support.go` |
| NetSem capacity | 500 | session config |
| ScanSem capacity | 3200 | `internal/net/network.go` `MaxScanConns` |
| `sweepMaxResubmit` | 500 | `protocol_probes/sweep.go` |
| `ownedMinPrefixBits` | 16 | `support/owned_netblock.go` |
| `ambientAdmitMinPrefixBits` | 20 | `support/owned_netblock.go` |
| `missListChunk` | 5000 Done IPs per statement | `protocol_probes/sweep_query.go` |
| `fqdnOSINTFirst` / `fqdnOSINTLast` | 20 / 40 | `registry/osint_bypass.go` |
| DNS attempts per query | 6 | `support/resolvers.go` |
| `lookupFailureInterval` | 1 minute per plugin | `support/lookup.go` |
| Prospeo `max_emails_per_domain` / `min_remaining_credits` | 25 / 0 | `datasources.yaml` options |
| Container `nofile` | 8192 | `compose.yaml` |
| `maxAnnouncedNetblocksForScope` (ASN fan-out backstop, 1.1) | 500 | `horizontals/plugin.go` |
| `MaxRecordsPerLocation` (shared-address cap, 1.1) | 25 | `support/shared_location.go` |
| `maxRDAPRangePrefixes` (per-IP RDAP range split, 1.1) | 8 | `api/rdap/ipaddr.go` |
| `maxRegisteredNetblocks` (netblocks per record walked, 1.1) | 64 | `horizontals/plugin.go` |
| `maxAdmittedNetblocks` (owned record's netblocks admitted, 1.1) | 256 | `api/rdap/ipnet.go` |
| `storeItemTimeout` (per stored name, 1.1) | 15 s | `support/database.go` |
| `detachedWriteTimeout` (write guard, 1.1) | 5 min | `sessions/write_guard.go` |
| `BrokenReverseZoneFailures` (per /24, 1.1) | 5 | `support/reverse_dns.go` |
| `BrokenForwardZoneNames` (distinct names per zone, 1.1) | 10 | `support/reverse_dns.go` |
| `ownedFillMaxBacklog` / `ownedFillCheckEvery` (1.1) | 2048 / 64 | `support/owned_netblock.go` |

# Appendix C — Production deployment model

30–50 isolated instances in AWS EKS against a shared PostgreSQL 17
behind pgBouncer. Instances **cannot coordinate** — admission control is
the orchestrator's job, by observing each instance's connection footprint
and inhibiting new launches near a red line.

All OSINT and DNS traffic egresses directly. All **active** traffic —
anything touching a target asset — must egress through a user-specified
proxy (Tor or residential). This is enforced on `hypermass-1.1` (13.1). DNS is explicitly **not**
active traffic, by policy: simple DNS queries are indistinguishable from
background noise, whereas port and service probing is a detectable,
attributable reconnaissance signal.

Each instance gets its own public IP, so per-source rate limits (e.g.
BGP.Tools) apply per instance rather than fleet-wide.

Production drives the engine through its API directly, not through
`oam_enum`. CLI-only behaviour (`enum`'s idle and timeout logic, `-silent`)
is therefore a development concern; engine and plugin behaviour is what
ships.

# Part 12 — Releases and naming

The first release is **Hypermass 1.0**, tag `hypermass-v1.0.0`
(annotated) on `5041be70`, the `service-detection` head after PR #10.

- **Tag names carry the fork's name.** The fork inherits all upstream
  tags, and both `v1.0.0` and `1.0.0` already exist (Amass's own 1.0).
  Plain version tags would collide. Use `hypermass-vX.Y.Z`.
- **Release notes** list changes since the previous fork tag (the first
  release: since `sd-freeze-2026-09-10`), grouped by area, with PR
  numbers.
- **Building a release.** `compose.yaml` builds both images from the
  repository URL. Track the branch with
  `https://github.com/prisoner881/hypermass.git#service-detection`, or pin
  a release with `#hypermass-v1.0.0`. Use the same ref for `enum` and
  `engine`, and rebuild with `--no-cache` after changing it.
- **What the rename did not change:** the module path, binary names
  (`/bin/enum`, `/bin/engine`, `ae_isready`), in-container paths
  (`/.config/amass`), and the upstream "OWASP Amass v5.1.1" strings in the
  banner and visualisations. Rebranding those is a separate, small patch.
- Older fork tags: `sd-freeze-2026-09-10`, the last known-good
  `service-detection` before the active-proxy merge work.
- **1.1 is not tagged yet.** `hypermass-1.1` is the development branch.
  When it is released, tag `hypermass-v1.1.0` on its head and write the
  notes from Part 13. Until then, build from the branch ref
  (`…/hypermass.git#hypermass-1.1`).

---

# Part 13 — `hypermass-1.1`: everything since release 1.0

Merged as PRs #11–#29 (`2b6b3936` … `e521102b`). Each section names the
commits, the files, and the run that exposed the problem. Measurements are
from the operator's runs against real targets; targets are named because
the incidents are referred to by name in commits and discussion.

## 13.1 Active egress through an operator proxy (PRs #11, #12)

Operator guide: `docs/active_proxy_egress.md`. Design rules:

- **Every `-active` connection** (port connect scans on both pipelines,
  HTTP probes, Protocol-Probes banner peeks and TLS certificate harvests,
  JARM) takes its dialer or client from **one decision point**:
  `support.ActiveDialer(sess, timeout)` / `support.ActiveHTTPClient(sess)`
  (`support/active.go`).
  - `active_proxy` set → the proxy dialer/client (SOCKS5/`socks5h`, HTTP
    CONNECT, `internal/net/active_egress.go`);
  - no proxy and `active_strict` (default **true**) → `ErrNoActiveEgress`,
    the operation is skipped and logged;
  - no proxy and not strict → a direct dialer / the Probe client.
- **Fail closed everywhere.** The old nil-means-direct fallbacks in
  `scanPorts`, `PeekBanner` and `dialAndGetCertChain` are gone; a nil
  dialer scans nothing. JARM is gated on `-active` like the other probes.
- **DNS is never proxied**, by policy (Appendix C), and neither are passive
  data sources. The source branch's `active_dns_resolver` was not ported.
- **Start-up health check.** `ActiveEgress.HealthCheck` probes the proxy
  before any work is dispatched; a dead proxy, or `-active` with strict
  and no proxy, refuses session creation (logged, and the API error
  details reach `oam_enum`).
- **No mid-run kill** (PR #12). A proxy that dies mid-run makes active
  operations fail; nothing goes out directly. Stopping affected engines is
  an external monitor's job. `ProxyError` and the SOCKS/CONNECT classifier
  remain for the start-up check. SOCKS5 reply 0x06 "TTL expired" (Tor's
  filtered port) is a target answer, not a proxy failure.
- **Config:** `active_proxy`, `active_strict`. CLI: `-active-proxy`,
  `-active-strict`. `Config.CheckActiveEgress` holds the policy with no
  side effects; the API handler calls only that, so `-active-strict=false`
  behaves exactly like `service-detection` (`CheckSettings` rewrites
  wordlists and must not run on API sessions).
- Proxy per-dial timeout 6 s (3× the 2 s direct connect-scan timeout).

## 13.2 Engine API (PRs #13, #14, #18)

- **`docs/engine_api.md`** documents every endpoint for orchestrator
  authors: job lifecycle as `oam_enum` performs it (create, log stream,
  seeds, idle detection, end-work, terminate), the session config schema
  (including the `net.IPNet` form `scope.cidrs` needs), assets, the log
  stream, fleet operation. Swagger (`docs/docs.go`, `docs/swagger.yaml`)
  regenerated with swag v1.16.6.
- **Four fixes:** bulk asset add no longer panics the engine on an asset
  the database refuses (nil entity dereference in a goroutine); the single
  asset handler returns 500/400 instead of dropping the connection; a
  config without `scope` gets 400 instead of a panic; the WebSocket log
  stream no longer leaks goroutines per message after a client leaves
  (`pubsub/logger.go`: one queue and pump per subscriber, `Unsubscribe`,
  the handler reads the connection and ends on disconnect or 60 s without
  pong).
- **`enum -scope-json`** (`internal/enum/scope_json.go`). The session
  scope lives only in engine memory and is gone when the session ends.
  The flag prints, just before termination (also on Ctrl-C and under
  `-silent`), one line: `HYPERMASS_SCOPE {"session":…,"fqdn":[…],
  "netblock":[…],"autonomoussystem":[…],"ipaddress":[…]}`. Lists sorted;
  a type that could not be read is listed under `"errors"`.
  `enum-companies.py` captures it for the report's Scope tabs.

## 13.3 DNS resolver override (PR #16)

Environment variables read by the engine at start-up
(`support/resolvers.go`), each falling back to the built-in behaviour:

| Variable | Meaning |
|---|---|
| `AMASS_ENGINE_RESOLVERS` | comma-separated resolver IPs, or a path to a file with one per line, replacing the built-in baseline list |
| `AMASS_ENGINE_RESOLVER_QPS` | aggregate queries/second cap across the whole trusted pool (0/unset = no cap) |
| `AMASS_ENGINE_WILDCARD_RESOLVER` | resolver for wildcard detection (default 8.8.4.4) |

A start-up line `trusted DNS resolvers: …` reports the choice, with a
warning if an override was set but held no valid address.

> **Not merged:** local branch `feat/resolver-per-ns-ceiling` (`4306bcc0`)
> raises the resolve library's fixed per-nameserver ceiling (~10 qps per
> record type) for an override list with a QPS budget, via a wrapper
> nameserver (`support/fast_resolver.go`). It was built and tested but
> never applied; ask before reviving it.

## 13.4 Scope: what grows it, and what now stops it

This was most of the 1.1 work. Read it before touching `horizontals/`,
`ip_netblock.go`, `whois/`, `api/rdap/` or `sessions/scope/`.

### 13.4.1 How scope grows (the paths)

| Path | Where | What it admits |
|---|---|---|
| Seeds | config `scope.domains`, `cidrs`, `asns`, `ips` | distance 0 |
| Registration records | `horizontals/reg_records.go` (`DomainRecord`, `IPNetRecord`, `AutnumRecord`) | a record whose registrant organization or address is in scope admits what it registers and expands the registrant |
| Organization / Location walk | `horizontals/org.go`, `location.go` → `expandFromContactRecord` | from an in-scope org or address, every contact record using it, and what those records register |
| TLS certificates | `horizontals/tls_cert.go`; `scope.Add(TLSCertificate)` adds the CN's registered domain | |
| Association | `sessions/scope/assoc.go` (`IsAssociated`) | domain/org/address linked to in-scope evidence |
| Netblock ownership | `support.AdmitOwnedNetblock` (RDAP contact email on a seed domain), plus session-end `FinishOwnedNetblockFills` | any size |
| ASN fan-out | `horizontals.addASNetblocksToScope` | small (≤ /20) announced IPv4 blocks of an in-scope ASN |
| Provenance IPs | `dns/ip.go` | the single IP an in-scope name resolves to (6.3) |

**Scope matching** (`sessions/scope/`): domains by suffix; IPs inside an
in-scope netblock or exact; netblocks by exact CIDR; **organizations by
exact lowercase name** (Name or LegalName; the fuzzy branch never fires at
the confidences used); locations by building number + street + city +
province (unit ignored). Scope can only grow; nothing is removed.

### 13.4.2 Shared-provider ASNs (PR #15, then revised in Phase 1)

A Cloudflare-fronted single domain (vistra.com) grew to ~500 netblocks of
CDN/cloud space and ~58k "open" ports: one admitted provider /24 led to
the provider's organization, its ASN, and the fan-out admitted the whole
ASN. Now:
- an ASN announcing more than **500** netblocks
  (`maxAnnouncedNetblocksForScope`) never enters scope, not even the AS
  itself (`VetoSharedASN`); 16 was tried first and caught companies that
  run their own networks (American Express 119, Bank of America 98);
- under the cap, the fan-out admits only small (≤ /20) IPv4 blocks.

There is **no provider list.** A curated list of provider ASNs was built
(local branch `fix/scope-review`, commit `38084016`, "G") and shelved: the
operator's position is that static lists of companies do not hold up over
time. Prefer data-driven signals.

### 13.4.3 Privacy proxies, shared addresses, role and placeholder names (PRs #17, #19, #20)

From crayon.co (a WHOIS-proxy address pulled in hundreds of unrelated
registrants) and blue.cl (grew into Salesforce Marketing Cloud):
- **Privacy/proxy detection** (`whois/privacy_detect.go`): "On behalf of
  <domain>", whoisproxy/domainsbyproxy/"Identity Protection Service",
  privacy-service mail domains and their subdomains, hashed mailboxes
  (32+ hex), per-domain stand-ins ("Registrant of example.com"), masking
  text. Placeholder contacts are skipped in every role.
- **Shared-address cap** (`support/shared_location.go`): an address used
  by more than 25 records (`MaxRecordsPerLocation`) is shared — neither
  admitted nor walked, logged once per session. Records are counted across
  every stored variant of the same building (number, street, city,
  province), because "Salesforce, Inc. 415 Mission St…" and "Attn:
  Accounts Payable 415 Mission St…" are different Location entities that
  scope matching treats as one. Shared verdicts are cached per process
  (keyed by database identity + entity ID).
- **Role names and non-names** (`support/role_names.go`): "Domain
  Administrator", "Hostmaster", "DNS Admin" (every word from a role
  vocabulary) and placeholders ("N/A", "None", "Private Person",
  "Internet Widgits Pty Ltd", values with no letters or digits) are not
  organizations: WHOIS and certificate storage no longer create them,
  horizontals neither admits nor walks them.
- Organization dedup no longer merges organizations on a shared address.

### 13.4.4 Hosting is not ownership (PR #19)

An in-scope netblock's registration record expands to its registrant only
when the block is **attributed to the target** (a contact email on a seed
domain, `IPNetRecordOwnedBySeed`). Being in scope because the target's
hosts sit on it makes the target a tenant, not the owner. Otherwise the
record is handled like an out-of-scope one: it expands only if its
registrant is already in scope, and that decision is logged.

### 13.4.5 Domains via records and certificates are queued (PR #20)

`processDomainRecord` queued the DomainRecord instead of the FQDN, so a
domain admitted by registration never got its second pass (subdomain
OSINT). And `scope.Add(TLSCertificate)` added the certificate's CN, which
only works when the CN is a registered domain; it now adds the CN's
registered domain (wildcard stripped) and the org/location handlers queue
that domain's FQDN.

### 13.4.6 Phase 1 scope vetoes: evidence against (PRs #21, #22)

Scope expansion used to look only for positive links. Phase 1 adds
**vetoes**: data showing an asset about to join scope belongs to someone
else.

**Setting:** `scope_vetoes` (top-level config field, also read from the
YAML options; `config/scope_vetoes.go`):
- `enforce` (default, and for empty/unknown) — block;
- `observe` — log `would decline` and keep the 1.0 behaviour;
- `off` — skip the checks.

**Framework** (`support/scope_decision.go`):
- `support.Decline(sess, reason, type, asset, plugin, kv…) bool` logs
  `scope decision` once per session/reason/asset (`action=declined` or
  `would decline`, `reason=…`, evidence fields) and returns whether to
  block. Reasons: `VetoResolutionOnly`, `VetoForeignRegistrant`,
  `VetoMergedCertificate`, `VetoSharedASN`.
- **Provenance:** `RecordScopeAddition(sess, asset, from)` keeps the
  shortest distance from the seeds (seeds 0; −1 unknown). Horizontals and
  association log `via=`, `from=`, `distance=` on every addition.
  Organization distance is keyed by normalized name (scope matches
  organizations by name and several entities share one); blocks admitted
  by ownership are one step from the seed domain of the matching email.
  **Distance is recorded, not yet enforced** (Phase 3).
- Per-session state is dropped when the session ends
  (`support.ForgetSession`, called from the engine's shutdown hook).
  Process-wide verdict caches are keyed by database identity + entity ID
  (`entityCacheKey`), because entity IDs are unique only per database.

**N2 — resolution alone no longer admits a netblock.** `ip_netblock.go`
and `bgptools/netblock.go` decline the "small block + in-scope name"
admission (`VetoResolutionOnly`). That gate admitted Cloudflare, AWS,
Akamai and Salesforce blocks (~80,000 third-party addresses for blue.cl).
Ownership is decided by registration:
- `support.RegistrationVerdict(ctx, sess, rec)` on an `IPNetRecord` or
  `AutnumRecord`: **owner** (a contact email on a seed domain, or a
  registrant organization in scope at confidence 100); **foreign** (a real
  registrant organization, not role/placeholder/care-of, not in scope,
  *and* a contact email on a non-freemail domain not in scope); otherwise
  **no information**.
- Horizontals declines a foreign record where it would otherwise admit
  what it registers or expand its registrant (`DeclineForeignRegistration`).
  Seeded CIDRs and ASNs are never declined.
- The target's own IPs are still authorized one at a time (6.3).

**N1 — explicit statements in the record.** Care-of and mail-drop text
(`c/o`, `care of`, `PMB 255`, `#` + 5 or more digits; `support/care_of.go`)
marks an address as not the registrant's: WHOIS and RDAP contact storage
keep the organization and email but do not link the address, and a stored
care-of address counts as shared at once (registered agents are caught on
an empty database). Care-of text in an organization field drops the
organization.

**M — merged certificates** (`support/merged_cert.go`). asset-db stores
certificates unique by serial number, and default/self-signed certificates
reuse serials, so one stored certificate can merge unrelated ones (a
serial-1 record linked 84 organizations). A certificate whose CNs span more
than one registered domain, or whose subject contacts name more than one
real organization, is not used by the certificate, organization or address
handlers, or by scope association (through `scope.SkipAssociationEvidence`,
a hook support registers because `scope` cannot import `support`).
Certificate contact records are keyed by issuer and subject as well as
serial.

### 13.4.7 Per-IP RDAP (Phase 1)

The netblock handler queries RDAP with each IP's BGP prefix, which for an
Internet provider's aggregate returns the provider's record, so a block
reassigned to the target inside it was never seen. `api/rdap/ipaddr.go`
(IPAddress **position 5**, after IP-Netblock at 4) queries RDAP **by
address** for IPs an in-scope name resolves to:
- skipped for non-routable addresses, addresses inside an in-scope
  netblock, and addresses an earlier answer this session already covers
  (`RDAPRangeKnown`);
- the answer's range is split into CIDR blocks (at most 8,
  `RangeToPrefixes`); blocks **more specific than the BGP prefix** (or
  ≥ /16 IPv4, ≥ /32 IPv6 with no BGP prefix) are stored as their own
  Netblock with a registration record, and the normal ownership check
  decides.

It first shipped at position 41, which Port-Prefilter holds, so the
engine failed to start (PR #22 moved it). `engine/plugins/load_test.go`
now catches that class of bug.

## 13.5 RDAP registrations stored under the range they register (PRs #23, #24)

RDAP answers a query for an announced /24 with the most specific
registration covering it, often larger (a /22 announced as four /24s). The
netblock handler stored the record under the /24 with the /22's start and
end addresses; asset-db **requires a record's CIDR to contain its own
start and end**, refused it, and the error was discarded. Every such block
lost its record, its contacts and therefore its ownership, on every run
(First Data's Asia-Pacific space for Fiserv: 198.184.0.0/21,
203.17.32.0/22, 202.14.196.0/22, all with fiserv.com contacts).

Now (`api/rdap/netblock.go`):
- the record is stored under the **largest CIDR inside the RDAP range
  that contains the netblock** (`registeredPrefix`; no limit on how many
  blocks the range splits into); the netblocks it covers share one record,
  each with its own `registration` edge;
- within the 30-day TTL the record is found by the **netblock's own
  registration edge**, not by CIDR; a netblock marked looked-up with no
  record is queried again;
- a record that cannot be stored is logged (`RDAP registration record not
  stored`, with the reason) and the netblock is not marked;
- the handler re-runs the ownership check when it links a netblock to a
  record, so a /24 linked after its siblings is still attributed;
- `admitParentNetblock` checks the record's ownership **once** before
  walking its linked netblocks (cap 256), so a provider record shared by
  many netblocks is never walked block by block;
- horizontals find a record's netblocks by incoming registration edges
  (cap 64, `getRegisteredNetblockEntities`); an owned record counts as in
  scope when one of its linked netblocks is;
- `AdmitOwnedNetblock` attributes each block **once per session**; it ran
  for every address in a block before, repeating the walk and the log line
  hundreds of times.

Known gap: an RDAP answer with only one of the registration / last-changed
dates is still not stored (asset-db requires both); seen on AFRINIC and
some APNIC records.

## 13.6 The database write path (PRs #25, #26)

**asset-db facts that drive this** (`repository/postgres/worker.go`):
- one **writer** connection (`PoolMaxConns: 1`) for all writes; a pool of
  readers;
- the writer batches queued writes from every caller into one transaction
  with a savepoint per write, and runs each write **under its caller's
  context**;
- if a caller's context expires while its statement runs, pgx cancels it
  by **closing the connection**, and every other write in the batch fails
  (`savepoint: conn closed`, `commit: conn closed`).

**asset-db must stay as it is** (no fork, no patch, no upstream PR). So:
- **Write guard** (`sessions/write_guard.go`): the session wraps its
  repository; every create and delete runs under a context the caller
  cannot cancel, bounded at 5 minutes (asset-db's own batch limit). The
  caller still waits only as long as its own context; if that expires it
  gets its error and the write completes in the background (writes are
  idempotent upserts). A write whose caller already gave up is not
  submitted. Reads pass through.
- **Per-name deadlines** (`support/database.go`, `storeEach`):
  `StoreFQDNsWithSource` / `StoreEmailsWithSource` gave a whole batch one
  30 s deadline, so the first 30 s of a large answer were stored and
  everything after failed (IP-THC returns up to 50,000 names: ~47,600 of
  Mailchimp's were dropped). Each name now gets 15 s; failures are logged
  once per batch (`failed to store names … failed=N stored=M error=…`).
  `StoreFQDNsWithSourceCount` reports the failures; IP-THC uses it to
  leave a lookup unmarked when names failed. The ~24 other callers still
  mark regardless.

**What remains:** the single writer is the throughput ceiling. During
large owned fills writes can queue for minutes; a write that waits past
the guard's 5 minutes still kills its batch (two seen on a 65k-address
fill before pacing, 13.9). `context deadline exceeded` from DNS during a
fill is a caller giving up on its write, not lost data in the batch sense,
but the caller (e.g. DNS-Reverse creating a PTR alias) skips its work for
that address this run.

## 13.7 BGP.Tools no-route answers and unrouted networks (PR #27)

BGP.Tools answers `<nil>` in the prefix field for an address no BGP route
covers. That was parsed as an error and logged per address (896 of 909
WHOIS errors on Blackbaud, whose 216.235.192.0/20 is mostly unannounced).
Now:
- `parseBGPToolsRecord` returns `errNoRoute` for `<nil>` or an empty
  prefix (parser split out for tests);
- a route more specific than /24 (IPv6 /48) is not carried globally, so
  `support.RecordUnrouted` marks the address's /24 (/48) for the session;
  BGP.Tools skips its other addresses, **IP-Netblock stops its 30-second
  wait** for their prefix, and the network is logged once (`no BGP route
  covers the network`);
- **port scanning skips unrouted addresses** (`EnsureOpenPortsScanned`,
  PR #29): no probe can reach them. They are still filled and get reverse
  DNS, and are not marked scanned.

## 13.8 DNS lookups that cannot succeed (PRs #28, #29)

`PerformQuery` returns at once on NXDOMAIN or "no record of this type";
`ErrFailedMaxDNSAttempts` means **all six attempts errored** (timeout,
SERVFAIL). Two waste patterns, both found on owned-block fills:
- **Reverse names got forward lookups.** DNS-Reverse creates an FQDN for
  each address's `in-addr.arpa` name and dispatches it; DNS-IP, DNS-CNAME,
  DNS-TXT and DNS-Subdomains then ran forward lookups on it. They now skip
  reverse names (`support.IsReverseDNSName`).
- **Broken reverse zones** (delegated to servers that don't answer, every
  name SERVFAIL; most of Blackbaud's): DNS-Reverse records PTR outcomes per
  /24 (/48); after **5** failures with none answered the zone is skipped
  for the session (`reverse DNS zone is not answering`). Expect some
  overshoot (a fill dispatches a whole /24, so lookups are in flight when
  the cap trips).
- **Broken forward zones** (internal AD/wireless zones delegated in public
  DNS; UB's `ad.med.buffalo.edu`, `wireless.buffalo.edu`): after lookups
  of **10 distinct names** in a zone (the name minus its first label) fail
  with none answered, forward lookups of the zone's other names are
  skipped (`DNS zone is not answering`). **A registered domain is never
  capped**, only zones below it.

Answered lookups (including NXDOMAIN) keep a zone open for the session.
All state is per session, so a fixed zone is retried next run.

## 13.9 Owned-fill pacing (PR #29)

A fill creates addresses far faster than the pipeline works through them,
and every address leads to further writes through the single writer
(13.6). Every address is still filled; the fill now **pauses while the
session's IPAddress backlog (queued + leased) is at 2,048 or more**,
checked every 64 addresses, and logs `owned-netblock fill paused` once per
fill; its finish line carries `paused=N`. The dashboard's `waiting` column
is the backlog's `queued` count, the same number the pacing reads.

On a repeat target the backlog is often full at the start for other
reasons: **Known-FQDN** dispatches every name ever stored under each seed
domain (no age limit), and their resolutions flood IPAddress. Fills then
wait until that replay drains. That is expected.

## 13.10 Open items on 1.1

- **Seed name match** (proposed, on hold by the operator's decision): a
  registrant whose normalized name equals a seed domain's label
  ("MailChimp" for mailchimp.com) would count as owner. Mailchimp's
  networks name "MailChimp" with contacts at intuit.com, so today they are
  read as **foreign** and their 20 /24s are declined.
- **Phases 2–4** of the veto plan (vendor delegation, reverse-DNS
  operators, seed fingerprint, distance limits, GLEIF, fan-in circuit
  breaker): see `docs/HYPERMASS_BRIEFING.md`.
- RDAP log line `relationship discovered … relation=registration` now
  shows the **record's** CIDR in `from=`, not the queried netblock's
  (cosmetic; introduced by 13.5).
- RDAP answers with only one event date are not stored (13.5).
- Domain WHOIS is attempted on hostnames that aren't registered domains
  (`failed to parse the WHOIS record for …trafficmanager.net`).
- `unspecified IP addresses are not allowed`, `location city/country
  cannot be empty` errors appear a few times per run; not traced.
- Only IP-THC retries a lookup whose names failed to store (13.6).
- The temporary `provenance scan authorization` Info line (6.3) is still
  there and is the busiest log line on large runs.
