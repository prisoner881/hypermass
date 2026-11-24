# Hypermass — Developer Briefing

This document explains **everything in Hypermass 1.2 that differs from
OWASP Amass v5**, and why it exists: what each change does, the problem
it fixed or the advantage it gives, and what is likely to break if it is
changed. It is written for any developer (or AI assistant) who picks up
the project, so that nothing in the fork looks arbitrary and every change
can be made knowing its consequences.

How the document is organized:

- **Part I — Orientation** (sections 1–3): what Hypermass is, how stock
  Amass v5 works, and a one-page map of every area the fork changed.
- **Part II — The changes** (sections 4–10), one section per area, each
  given the same treatment: what stock Amass did, what Hypermass does, how
  it works, why, and the **impact of changing it**:
  4. Active service discovery (port pre-filter, Protocol-Probes, Tech-Stack…)
  5. Active egress through a proxy
  6. Data sources
  7. Scope: what the engine treats as the target's
  8. DNS
  9. Database and engine reliability
  10. Engine API, CLI and operations
- **Part III — Working on Hypermass** (sections 11–17): a change-impact
  guide, the standing policies, the delivery workflow, diagnostics,
  building and testing, traps, and known issues.
- **Appendices**: pipeline positions, constants, the incident history,
  and the full agreed design for the remaining scope phases.

Companion documents in `docs/`:

| Document | Use it for |
|---|---|
| `CHANGELOG.md` | Every change in date order, by release and PR, reconstructed from the Git history |
| `MAINTAINERS.md` | The code-level reference: file by file, with the long incident write-ups |
| `engine_api.md` | The engine REST API for orchestrator authors |
| `active_proxy_egress.md` | Operator guide to active-egress proxying |
| `hypermass_functions.sql` | The reporting SQL functions (section 10.8) |

Paths are relative to the repository root; `engine/plugins/` is omitted
where the context is obvious (`support/portscan.go` means
`engine/plugins/support/portscan.go`). State as of `hypermass-1.2` at
`01b6e26b` (PR #35).

---

# Part I — Orientation

## 1. What Hypermass is

### 1.1 Purpose and users

- A fork of **OWASP Amass v5** (engine, `oam_enum` client, plugins),
  maintained at **`github.com/prisoner881/hypermass`** (renamed from
  `prisoner881/amass`). The fork point is upstream **v5.1.1** (`79299dce`).
  The Go module path is still `github.com/owasp-amass/amass/v5`, and the
  binaries and banner were not rebranded.
- Used by **FortifyData**, a licensed security company, for authorized
  external attack-surface enumeration of client organizations.
  Enumerations are **thorough by policy**: the operator would rather spend
  time than miss assets.
- Stock Amass is mostly a **passive discovery** tool with light probing.
  Hypermass turns it into an **attack-surface mapper**: it finds the
  target's services on every port that matters, identifies the software
  and versions on them, routes all active traffic through an approved
  proxy, decides much more carefully what belongs to the target, and
  survives very large, long runs against a shared production database.

### 1.2 Deployment

- **Production:** 30–50 isolated engines on AWS EKS, one session per
  engine, against a shared PostgreSQL 17 behind pgBouncer, driven through
  the engine REST API (not `oam_enum`).
- **Development and testing:** the operator's single host. Docker Compose
  in `~/amass-docker-compose` builds `engine` and `enum` from the
  `hypermass-1.2` branch on GitHub and runs libpostal (`postal`) and
  syslog. The database is the PostgreSQL server named in `config.yaml`
  (the `assetdb` service in `compose.yaml` is not used). Enumerations are
  queued by `enum-companies.py` (section 10.9).
- **The engine container needs `nofile` 8192** (section 4.1). This is a
  deployment setting, not code.

### 1.3 Versions and branches

| Branch / tag | State |
|---|---|
| `hypermass-1.2` | **Active.** Branched from `hypermass-1.1` at `f4e002e3`; PRs from #33 on. The operator's `compose.yaml` builds from it. |
| `hypermass-1.1` | Everything since 1.0, PRs #11–#32. Untagged. The base of 1.2. |
| `service-detection` | **Frozen** at `176be5e5` (release 1.0 plus the MAINTAINERS upload). Never commit to it; check it is unchanged after every merge. |
| `hypermass-v1.0.0` | Release 1.0 tag, on `5041be70`. |
| `sd-freeze-2026-09-10` | Last known-good state of the pre-release era. |

Fork tags must carry the fork's name (`hypermass-vX.Y.Z`): the repository
inherits every upstream tag, and plain `v1.0.0` already exists.

What each release added, in one line each (details in `CHANGELOG.md`):
- **Pre-release (Aug–Sep 2026):** port pre-filter, Protocol-Probes,
  Tech-Stack, Page-Links, new data sources, session-end work, owned
  netblocks, many upstream defect fixes.
- **1.0 (Oct 14):** a review pass: honest lookup marking, PTR
  attribution, Prospeo, URLScan, the netblock admission fix, PassiveTotal
  removed.
- **1.1 (Oct 15 – Nov 5):** active-egress proxying, the engine API
  reference and fixes, the resolver override, the scope overhaul with
  vetoes, RDAP registration storage, the database write guard, DNS waste
  caps, wappalyzergo 0.3.8.
- **1.2 (Nov 24 –):** the session-end sweep's batched query restored,
  wappalyzergo 0.3.11, operator tools in `utility/`.

### 1.4 People and roles

- **The operator / maintainer** (GitHub `prisoner881`) owns the
  repository, runs every enumeration and makes every decision. They read
  diffs, push back on weak reasoning, and expect findings backed by data.
- **Keith** drives the engine directly through its API, as production
  does. Every feature must work for an engine-only caller with nothing but
  the session config (no `oam_enum`, no operator scripts).
- **The assistant** investigates, designs, writes code, tests and
  documentation, and delivers changes (section 13). It cannot reach the
  operator's host, database or logs; everything it learns about a run comes
  from output the operator pastes.

---

## 2. Stock Amass v5 in brief

Enough of the upstream design to understand what the fork changes. The
long version is MAINTAINERS Part 1.

- **Engine, sessions, CLI.** The engine (`/bin/engine`) is a long-running
  service with a REST API on port 4000. A client (`oam_enum`, or any
  orchestrator) creates a **session** with a configuration (scope seeds,
  transformations, data sources), submits seed assets, watches the log
  stream, and terminates the session. Each session has its own scope,
  backlog, semaphores and HTTP clients.
- **Assets and the database.** Everything is an Open Asset Model (OAM)
  asset (FQDN, IPAddress, Netblock, AutonomousSystem, Service,
  TLSCertificate, Organization, Location, ContactRecord, DomainRecord,
  IPNetRecord, …) stored by **asset-db** as an `entity` plus typed table
  row, with labelled `edge`s between entities and `entity_tag`s
  (properties) on them. Edge labels must be ones OAM's `relation.go`
  allows, or the write is rejected silently.
- **Pipelines and positions.** Each asset type has a pipeline. Plugins
  register **handlers** for an asset type at a numbered **position**; an
  event passes through positions in order. A handler can be **exclusive**
  (sole owner of its position) or share it; a shared position becomes a
  `Parallel` stage that handles **one event at a time**. Handlers have an
  instance count (4/16/32: `Min`/`Mid`/`HighHandlerInstances`).
- **Backlog and dispatcher.** Every asset event is a row in a per-session
  SQLite backlog (queued → leased → done). The dispatcher claims rows and
  feeds pipelines; a finished element is Acked. Sessions run with lease
  TTL 0, so a lease is never reclaimed.
- **Transformations and TTL.** The config's `transformations`
  (`FQDN->ALL`, `Netblock->RDAP`, …) decide which plugins run for which
  asset types (by matching a handler's `Transforms`) and how long a result
  stays fresh (TTL in minutes). A plugin records a lookup by writing a
  `last_monitored = <source name>` tag; within the TTL it skips the asset.
  **The source name is the TTL key**, so two plugins with the same source
  name share one slot.
- **Scope and horizontals.** The session scope starts from the seeds
  (domains, IPs, CIDRs, ASNs) and grows during the run: names under an
  in-scope domain are in scope by suffix, and the **horizontals** plugin
  adds assets associated with in-scope ones (same registrant organization,
  same street address, same certificate, an ASN's announced netblocks).
  Scope only grows.
- **Active vs passive.** `-active` enables probing (stock: HTTP probes
  on the configured ports, JARM ran regardless). Everything else is
  passive: DNS, OSINT data sources, WHOIS/RDAP.

---

## 3. The changes at a glance

| Area | Problem in stock Amass v5 | What Hypermass does | § |
|---|---|---|---|
| Port pre-filter | HTTP-probed every configured port on every in-scope IP: millions of attempts, almost all to closed ports | A TCP connect scan first; probes go only to open ports. ~99.9% of probes skipped; a 48 h run became 6 h | 4.1–4.2 |
| Non-HTTP services | Only web services were identified | Protocol-Probes: banner reads, Recog fingerprints, TLS certificate harvest on any open port | 4.4 |
| Software and versions | No web-technology fingerprinting | Tech-Stack: Wappalyzer over every fetched page; per-service product and version | 4.6 |
| Missed services | An IP could reach the probes before its ports were known | Session-end sweep re-probes those IPs; owned netblocks filled address by address | 4.5 |
| Link provenance | Hostnames in pages were not recorded with their source | Page-Links stores every linked host with the page it came from | 4.8 |
| Active egress | Active traffic left from the engine's own address | Every active connection goes through an operator proxy or not at all | 5 |
| Data sources | Failed lookups recorded as done (sources went dark for weeks unnoticed); several sources missing or broken | Lookups marked only when answered; 7 new sources; broken ones fixed or removed | 6 |
| Scope | Grew by weak association: one CDN netblock, privacy-proxy address or role name pulled in thousands of unrelated assets, all then scanned | Ownership decided by registration; data-driven vetoes; owned netblocks admitted at any size; target IPs on shared hosting authorized one at a time | 7 |
| DNS | Fixed resolver list; up to 10 attempts per failure; lookups wasted on dead zones | Resolver override; 6 attempts; dead reverse and forward zones capped per session | 8 |
| Reliability | Deadlocks, hangs, stranded leases, OOM, and lost database writes on large runs | Each root-caused and fixed; writes guarded against callers' timeouts | 9 |
| API, CLI, operations | Engine API crashes and leaks; scope lost at session end; no progress visibility | API fixes, new endpoints, `-scope-json`, session-end hook, dashboard, reporting SQL | 10 |

Two cross-cutting rules came out of this work and apply everywhere:

1. **Mark a lookup done only when it really completed** (section 6.1). A
   failure recorded as "nothing found" hides the asset for the whole TTL,
   in later sessions too, silently.
2. **A decision made after an asset has passed its consumer has no
   effect** unless something re-examines the asset. That is why the
   owned-netblock fill and the session-end sweep exist (section 4.5).

---

# Part II — The changes

Each section follows the same pattern: **stock** (what upstream did),
**Hypermass** (what the fork does and how), **why** (the problem or the
advantage), and **impact of changing it** (what depends on it, what
breaks). MAINTAINERS has the file-level detail and long incident write-ups.

## 4. Active service discovery

With `-active`, Hypermass finds every listening service on the configured
ports of every in-scope IP, identifies the software behind it, and records
where each host was found. Stock Amass only made HTTP requests to every
configured port. This is the largest body of fork code (pre-release, Aug–
Sep 2026, then fixed in 1.0).

How the pieces fit, on the IPAddress pipeline:

```
pos 41  Port-Prefilter    (32 instances)  TCP connect scan -> open_port tags
pos 42  HTTP-Probes (IP)  (32)            HTTP/HTTPS on open ports -> Services
pos 43  Protocol-Probes   (16)            banners, Recog, TLS certs on open ports -> Services
Service pipeline: JARM (42), Page-Links (43), Tech-Stack (44) process each Service
FQDN pipeline pos 41: HTTP-Probes (FQDN) triggers scans of the name's IPs, then probes by name
Session end: owned-netblock fill + Protocol-Probes sweep
```

Position order is load-bearing: 41 finishes before 42 and 43 run for the
same event, so the probes read ports the pre-filter just stored.

### 4.1 Port pre-filter (`support/portscan.go`, `service_discovery/port_prefilter/`)

**Stock:** HTTP-Probes made an HTTP and an HTTPS request to every port in
`scope.ports` on every in-scope IP. On a large estate that is millions of
connection attempts, almost all to closed ports.

**Hypermass:** a cheap TCP connect scan runs first, and every probe reads
its result.
- Handler `Port-Prefilter-Handler`: IPAddress pos 41, exclusive, 32
  instances, `Transforms: [Service]`, `-active` only. Its dialer comes
  from the active-egress decision point (section 5).
- `EnsureOpenPortsScanned` is the single entry point (the FQDN path uses
  it too). It skips IPs that are out of scope, non-routable (4.10) or in
  an unrouted /24 (8.4; not marked, so a later session retries).
  Concurrent calls for one IP collapse through a `singleflight.Group`.
- `scanPorts` dials up to `maxConcurrentPortsPerIP = 100` ports at once;
  each dial holds a **ScanSem** slot (cap `MaxScanConns = 3200`, separate
  from NetSem's 500, section 9.5). A completed connect means open; nothing
  is read. A nil dialer scans nothing (fail closed). Direct dial timeout
  2 s.
- Results are `open_port = "<n>"` and `open_port_count` tags on the IP,
  then `PruneStalePortData` deletes `open_port` values not seen in this
  scan (by value, never after a cancelled scan), then `last_monitored =
  Port-Prefilter`. Readers use `OpenPortsForIP(…, since)`, filtered on
  `updated_at` within the **IPAddress→IPAddress** TTL
  (`PrefilterTTLStartTime`).

**Why:** measured on a large public university, ~99.9% of probes were
skipped and a 48-hour run took 6 hours. Pruning fixes a false positive:
tags upsert by value, so a port open once would otherwise be reported open
forever on a persistent database.

**Impact of changing it:**
- **File descriptors.** 32 instances × 100 ports = 3,200 sockets, plus
  FQDN-path scans (16 × 100) and NetSem's 500: ~5,300 against the
  container's `nofile` 8192. At Docker's default 1,024, every plugin's
  sockets failed silently; that is how it was found (twice). Raising the
  concurrency or instance count means raising `nofile` in `compose.yaml`
  and the EKS pod spec.
- **Gating.** With no `Transforms`, the handler never ran under
  `IPAddress->ALL` (owned-block IPs and `-addr`/`-cidr` seeds went
  unscanned: 17 of 1,022 addresses). Excluding Service from
  `IPAddress->ALL` turns off the pre-filter and both probes together.
- **TTL.** If no transformation matches IPAddress→IPAddress, every active
  probe of IPs stops silently.
- **Write first, prune after, never prune a partial scan.** Reordering
  creates a window with no ports, or deletes ports that were never
  reached. Known risk: a proxy that dies mid-run makes every dial fail
  without cancelling the context, so a scan "completes" with zero ports and
  prunes the IP's stored ports (section 17).
- The repository's `resources/config.yaml` keeps the stock 6 ports; the
  operator's config uses the nmap top 100 (`utility/config.yaml`).

### 4.2 Port ordering and decoy detection (`support/portpriority.go`, `portfreq_data.go`)

**Hypermass:** consumers sort open ports by real nmap-services frequency
(8,380 TCP ports in a generated map), so likely services are probed first.
An IP answering on more than 50 ports (`LikelyDecoyThreshold`) is treated
as a decoy, typically a WAF that SYN-ACKs everything, and its probes get a
90 s budget (`DecoyTimeBudget`).

**Why:** bounded time on decoys; useful results first.

**Impact of changing it:** nothing logs a decoy; with the stock 6-port list
the threshold can never trip; in HTTP-Probes the budget stops waiting but
requests already started still go out.

### 4.3 HTTP-Probes changes (`service_discovery/http_probes/`)

**Stock:** probed every configured port, always marked the asset done,
used the Probe client directly, wrote `Protocol: "TCP"`, 16 IP instances.

**Hypermass:**
- Ports come from the pre-filter. The IP handler (pos 42, now 32
  instances) only reads them. The FQDN handler (pos 41) triggers scans of
  the name's IPs (`OpenPortsForFQDN`, up to 5 CNAME hops) and builds URLs
  from the name so SNI is right.
- The HTTP client comes from the active-egress decision point (section 5).
- The asset is marked done only when something was probed.
- Port edges are `PortRelation{Name: "tcp_port_<n>", Protocol: "tcp"}`;
  consumers compare protocol case-insensitively because old rows say `TCP`.

**Why:** probe only what is open; never send active traffic outside the
proxy; never record a probe that did not happen.

**Impact of changing it:**
- An FQDN whose IPs are all out of scope is not probed (stock probed every
  in-scope name). Names on third-party hosting are probed only because
  DNS-IP authorizes their exact IPs (section 7.4); removing that
  authorization silently drops them.
- The IP handler's banner pre-peek (meant to skip HTTP on SSH/mail ports)
  passes a nil dialer and has done nothing since active egress (section
  17). Fixing it adds a second connection per port.

### 4.4 Protocol-Probes (`service_discovery/protocol_probes/`)

**Stock:** no non-HTTP service identification.

**Hypermass:** for each routable, in-scope IP with fresh open ports
(IPAddress pos 43, 16 instances, source confidence 80):
1. **Banner peek:** connect, one read of up to 4,096 bytes within 2 s.
2. **Classify:** `SSH-` prefix → SSH; other data → banner; nothing →
   silent.
3. **Recog** (`runZeroInc/recog-go`, fingerprints embedded, no external
   service) matches banners. The fingerprint set depends on the
   classification: `ssh_banners.xml` for SSH; SMTP, FTP, POP, IMAP, NNTP,
   telnet (in that order) for other banners. `BannerCandidates` tries the
   full banner, then forms with the protocol greeting stripped (`+OK`,
   `220 `, `* OK`, `SSH-2.0-`), then first and last lines. Recog matches
   the field after the greeting, so without this normalization almost
   nothing matched.
4. **TLS harvest** on silent ports: a handshake (SNI = an in-scope name
   for the IP if any). Only after a successful handshake is a `tls`
   Service created and the chain stored, with the parsed leaf passed on so
   TLSCert-Expansion links its names.
5. Services (`ServiceWithIdentifier(addr, "tcp", port)`, edge
   `tcp_port_<n>`) are **dispatched**, so JARM, Page-Links and Tech-Stack
   process them. Recog matches become Product and ProductRelease
   (section 4.6), with an OS match as a separate Product.

**Why:** finds SSH, mail, FTP, LDAP/IMAP over TLS, VPN portals and their
versions, and certificate names on non-HTTP ports: much of an attack
surface that is not a website.

**Impact of changing it:**
- An IP with no ports yet returns **without marking**. That is what the
  session-end sweep (4.5) catches; marking it would hide it for the TTL.
- The `tls` Service must be created only after a handshake succeeds, or
  every silent port (RDP, databases, decoys) becomes a bogus Service.
- The edge must be named `tcp_port_<n>` like HTTP-Probes': an unnamed
  edge duplicated the IP→Service edge on SQLite and blanked HTTP-Probes'
  label on PostgreSQL.
- The banner-candidate order matters (full banner first, for the rare
  pattern that includes the greeting).
- The IP is marked even if every peek failed (for example a dead proxy).

### 4.5 Session-end work: owned fill and the Protocol-Probes sweep

**Stock:** nothing after the first pass; the client waited for idle and
terminated.

**Hypermass:** once the first pass goes idle, the client calls `POST
/sessions/{id}/end-work`, which runs one hook, once per session:
1. **`FinishOwnedNetblockFills`** (section 7.3): fills owned netblocks
   attributed late, then waits up to 3 h for the IPAddress backlog to
   drain.
2. **`SweepMissedIPs`**: finds IPs that finished with fresh `open_port`
   tags but no fresh Protocol-Probes mark and resubmits up to 500 of them
   (`sweepMaxResubmit`).
   - **Batched path:** one PostgreSQL query per 5,000 Done IPs (`missListSQL`:
     open ports, not probed, resolved from a name under a seed or runtime
     scope domain). Chunked, indexed per-IP probes, 90 s per chunk.
   - **Walk:** each IP checked one at a time with several lookups. Used
     when the batch cannot run (SQLite), and for the IPs of a chunk whose
     query failed. After 3 failed chunks in a row the rest are walked.
     The sweep logs why it walks.
   - Then it waits up to 15 min for the requeued IPs to drain.
3. **`ForgetSession`** drops per-session state (section 7.5).

Progress is exposed at `GET /sessions/{id}/end-work` (phase, candidates,
requeued, IP backlog counts) and shown by the dashboard (10.9).

**Why:** within one pass an IP can reach Protocol-Probes before another
path finished scanning its ports; and ownership is often established after
an owned block's addresses were already processed. Without this, those
services are never probed.

**Impact of changing it:**
- **Never run the hook on terminate, Ctrl-C or engine shutdown.** Until
  1.0 it did: stopping a run started hours of new scanning, and shutdown
  ran it twice, the second time after the dispatcher stopped.
- **Never type-assert `Session.DB()`.** It returns the write guard
  (section 9.2). The sweep's batched path was silently dead from PR #26
  until 1.2 because of exactly that (113,047 IPs walked one at a time on
  one run). Unwrap with `Unwrap()`.
- The client must stay connected until the hook reports done; `oam_enum`
  does, with a 2-minute safety net (section 10.4).
- `ForgetSession` runs only on this path; a session ended any other way
  keeps its process-wide decision state (section 17).

### 4.6 Tech-Stack and product identity (`enrich/techstack.go`, `support/product.go`)

**Stock:** no web-technology fingerprinting.

**Hypermass:** Tech-Stack (Service pos 44, 16 instances, confidence 70)
runs Wappalyzer (`projectdiscovery/wappalyzergo` v0.3.11) over each
Service's stored headers and body. For each technology: a Product
(`Type: software`, categories in `Category`, properties `icon`, `website`,
`cpe`), `product_used` Service→Product, a ProductRelease with `release`
Product→Release, and a second `product_used` Service→Release so each
host's version is recoverable. **Angular:** wappalyzergo never evaluates
DOM rules in its static path, so modern Angular is never detected;
`detectAngular` reads `ng-version="X.Y.Z"` itself (guarded against double
storage if a future library version detects it).

**Product identity:** IDs are `lower(name) + "-" + hash`, release names
`lower(name) + " " + version`, so Wappalyzer's "Nginx" and Recog's "nginx"
are one entity (on PostgreSQL the second spelling violated the unique
natural key and was lost).

**Why:** per-service software and versions for vulnerability exposure;
one entity per product estate-wide.

**Impact of changing it:**
- Product is global (key = name); count `product_used` edges, not Product
  entities, to measure identification. Without the Service→Release edge,
  versions per host are lost.
- Only four edge labels may leave a Service (`provider`, `certificate`,
  `terms_of_service`, `product_used`); an invented label (`release_used`
  was tried) is rejected silently.
- Before bumping wappalyzergo, confirm the exported API and whether the
  static path now evaluates DOM rules (the last three bumps: no change).
- Frameworks versioned only at runtime (Vue, Next, Nuxt) cannot be
  versioned from static bytes; that is a ceiling, not a bug.

### 4.7 JARM (`jarm.go`, `support/fingerprinting.go`)

**Stock:** fingerprinted the Service entity instead of its host, so it
produced zero fingerprints in every run; it also ran without `-active`.

**Hypermass:** fingerprints the FQDN or IP behind the Service, requires
`-active`, dials through the active-egress dialer for all ten probes, and
compares protocol case-insensitively. The result is edge property `JARM`
on the port edge. It needs a fresh `certificate` edge, so SSH and banner
Services are skipped.

**Why:** TLS-stack fingerprints that actually exist, and no active traffic
outside the proxy. The bug was found by logging one discarded error after
three wrong theories from reading code (MAINTAINERS 11.2).

### 4.8 Page-Links (`pagelinks.go`)

**Stock:** no extraction of hostnames from fetched pages.

**Hypermass:** Service pos 43, 16 instances, `-active`, confidence 60.
Tokenizes each stored page body and reads `href`, `src`, `srcset`,
`action`, `formaction`, `data`, `poster`, `cite`, `longdesc`, `xmlns`.
Every hostname is stored (scope gating keeps out-of-scope names inert),
with provenance: `URL(page) -file-> File -contains-> URL(link) -domain->
FQDN`, plus an origin anchor from the page URL to its host. Fragments are
stripped; at most 1,000 URLs per page (hostname extraction is never
capped).

**Why:** finds names the target's own pages link to, and answers "which
page linked this host" (the report's TP Links tab uses it).

**Impact of changing it:** the origin anchor is the only traversable entry
point from a host to its pages (FQDN has no outgoing relation to URL).
Storage cost varies by site (~6 to ~81 URL entities per page).

### 4.9 TLS certificate enrichment (`enrich/tls_cert.go`)

Certificate contact records are keyed by serial **and** issuer and
subject (stock: serial only), because default and self-signed
certificates reuse serials and unrelated certificates' contacts merged. A
placeholder subject organization ("Internet Widgits Pty Ltd") no longer
becomes an Organization (section 7.7).

### 4.10 Non-routable addresses (`support/nonroutable.go`)

`IsNonRoutableAddress`: private (RFC 1918/4193), loopback, link-local,
multicast, unspecified and reserved ranges. Never scanned, probed,
authorized into scope or swept. The DNS records are still stored: an
internal address in public DNS is itself a finding for the client.

---

## 5. Active egress through a proxy

**Stock:** all active traffic (HTTP probes, JARM) left from the engine's
own network address, through any of several code paths.

**Hypermass (1.1, PRs #11, #12):** every `-active` connection goes through
one decision point and an operator proxy, or does not happen.
- **Decision point** (`support/active.go`): `ActiveDialer(sess, timeout)`
  and `ActiveHTTPClient(sess)` return the proxy dialer or client when
  `active_proxy` is set; `ErrNoActiveEgress` ("refusing to send active
  traffic over the default network") when `active_strict` is on (the
  default); and a direct dialer or the Probe client only when strict is
  off. Every active path uses it: Port-Prefilter, the FQDN port scan,
  HTTP-Probes, Protocol-Probes (peeks and TLS harvests) and JARM. The old
  "nil dialer means dial directly" fallbacks were removed; a nil dialer
  now does nothing.
- **Proxies** (`internal/net/active_egress.go`): `socks5://` and
  `socks5h://` (names resolved by the proxy), `http://` and `https://`
  (CONNECT, Basic auth from the URL). Dial timeout 6 s; HTTP client
  timeout 30 s.
- **Start-up check:** session creation is refused for `-active` with
  strict and no proxy, and when a configured proxy fails a health check
  (one connection through it to `1.1.1.1:443`). The reason reaches the
  client.
- **No mid-run kill** (PR #12): a proxy that dies mid-run makes active
  operations fail and nothing goes out directly. Stopping affected engines
  is an external monitor's job.
- **Reply classes:** SOCKS "TTL expired", refused and unreachable are the
  target's answer (a filtered or closed port); general failure, ruleset
  refusal and unsupported command or address are proxy errors.
- **Config:** `active_proxy`, `active_strict` (top level or `options:`;
  API JSON that omits `active_strict` gets true). CLI: `-active-proxy`,
  `-active-strict`. `Config.CheckActiveEgress` validates without side
  effects.

**Why:** production must send active traffic only from approved egress,
and must fail closed rather than leak when the proxy is missing or down.

**Impact of changing it:**
- **Any new active code must take its dialer or client from
  `ActiveDialer`/`ActiveHTTPClient`.** A direct `net.Dial` or a default
  HTTP client bypasses the proxy.
- **DNS and passive sources are never proxied**, by policy. (The source
  branch's DNS proxying was deliberately not ported.) FQDN-based probes
  still let the proxy resolve target names.
- The API calls only `CheckActiveEgress`, not `CheckSettings`:
  `CheckSettings` also rewrites wordlists and must not run on API sessions.
- The operator currently runs with `-active-strict=false` and no proxy
  (`enum-companies.py`), so active traffic goes direct on the development
  host.
- Known gaps (section 17): with SOCKS5 the 6 s timeout covers reaching the
  proxy, not the CONNECT reply, so a filtered port behind Tor can hold a
  scan slot for minutes; a proxy refusal mid-run looks like a closed port;
  the health check runs whenever `active_proxy` is set, even without
  `-active`.

---

## 6. Data sources

Hypermass adds sources, repairs broken ones, and changes one rule that
applies to all of them.

### 6.1 The lookup-outcome rule (`support/lookup.go`)

**Stock:** every data-source plugin marked the queried asset done
(`last_monitored`) after every lookup, whether or not the source answered.

**Hypermass (1.0, PRs #5, #7):** an asset is marked only when the source
**answered**, even with "nothing found". Transport errors, non-200
statuses, rate limits, skipped calls and undecodable bodies leave it
unmarked, so the next session retries. `HTTPLookupFailure(resp, err)`
gives the shared test; `LogLookupFailure` logs `lookup failed; not marked,
will retry next session` (with `reason`, at most once per plugin per
minute, to the engine log).

**Why:** a rejected key, an exhausted quota, a 429 or a timeout looked
exactly like "no results" and hid the asset for the whole TTL, usually
with no log line. URLScan was dark for weeks this way; with a 30-day
Netblock RDAP TTL, one timeout hid a block's ownership evidence for a
month.

**Applied to:** URLScan, HackerTarget, crt.sh, CertSpotter,
SubdomainCenter, DNSDumpster, AlienVault, DNSRepo, RapidDNS, IP-THC,
Prospeo, RDAP, WHOIS, GLEIF. **Not yet:** CommonCrawl, DNSHistory,
SiteDossier, and stock BinaryEdge, Chaos, LeakIX, SecurityTrails,
VirusTotal, ZETAlytics, Grep.App, Aviato.

**Impact of changing it:** any new or modified source must follow the
rule, and must decide carefully what counts as an answer (an empty 200 is
an answer; a quota notice in a 200 body is not).

### 6.2 New sources

All subdomain sources run only on apex names (`HasSLDInScope`, which
Known-FQDN sets on exact scope domains), need an FQDN→FQDN
transformation, store through `StoreFQDNsWithSource` (15 s per name,
section 9.3), and follow 6.1 unless noted.

| Source | Endpoint and auth | Pos, confidence | Notes |
|---|---|---|---|
| **AlienVault** | OTX `…/indicators/domain/{apex}/passive_dns`, `X-OTX-API-KEY` | FQDN 22, 70 | 1 req/s; a rejected key moves to the next key; in-scope names only; ~5 names per apex |
| **CertSpotter** | `api.certspotter.com/v1/issuances`, optional `Authorization: Bearer` | 22, 100 | Pages until empty; one page per 2.4 h without a key (process-wide), so **needs a key** in practice; honours `Retry-After` |
| **CommonCrawl** | `collinfo.json`, then the 6 newest collections' CDX APIs | 25, 60 | Restores v4's source; up to 7 requests per apex; **still marks every lookup** |
| **DNSDumpster** | `api.dnsdumpster.com/domain/{apex}`, `X-API-Key` (required) | 25, 80 | One page (free tier 50 records) |
| **SubdomainCenter** | `api.subdomain.center/?domain={apex}`, optional key | 25, 70 | Restores v4's source; free tier up to 500 names |
| **URLScan** | `urlscan.io/api/v1/search/?q=domain:{apex}`, `API-Key` (required) | 25, 70 | Sends its own User-Agent (1.0, PR #8: urlscan.io answered Amass's browser User-Agent with 429 before checking the key). Stores result hosts regardless of scope, an FQDN→IP `dns_record` edge per result, and `ptr_record` edges. Its ASN search was removed (58,000+ unrelated names) |
| **IP-THC** | `ip.thc.org` CSV: subdomains, reverse CNAMEs, and names seen on a /24 | FQDN 25 / IP 22, 70 | No auth; 2 s pacing; marks only when every name stored. The IP half runs only for IPs in seed-owned netblocks and stores **names only** (its rows are passive forward DNS, not PTR) |

**Why:** more passive coverage per apex at no cost or low cost; CT logs
and passive DNS find names no other source has.

**Impact of changing them:**
- Several share position 25 or 22, which is a one-event-wide `Parallel`
  stage: a slow source holds up the others (the OSINT bypass gate, 7.10,
  keeps discovered names out of it).
- URLScan is effectively a horizontal source: its out-of-scope names and
  IPs enter the graph, and its TTL-0 `dns_record` edges present
  historical resolutions as current A records (they feed
  `HasInScopeFQDN` and the IP report).
- IP-THC's per-/24 dedup and CommonCrawl's collection cache last for the
  engine process, not the session (section 17).
- Several sources have no entry in the stock `datasources.yaml`; the
  operator's file (`utility/datasources.yaml`, keys blanked) shows the
  names.

### 6.3 Changed and removed sources

- **crt.sh:** its source name said "HackerTarget". The two shared one TTL
  slot (section 2), so whichever ran first marked it and the other
  skipped; HackerTarget was effectively dark, and its findings were filed
  under the wrong source. Fixed to `crt.sh`. **Lesson:** a source name is
  a TTL key; never reuse one.
- **HackerTarget:** its "API count exceeded" notice (plain text, HTTP 200)
  is a failure; other plain text is still an answer (retrying would spend
  the quota).
- **DNSRepo:** skips empty credentials; tries each key, then the public
  page.
- **RapidDNS:** failures unmarked; an empty 200 is an answer.
- **DNSHistory, SiteDossier:** their 19-page loops stop at the first
  non-2xx or empty page. A blocked source used 19 rate-limiter tokens per
  seed for nothing and throttled the FQDN pipeline. They still mark every
  lookup and log nothing when they stop.
- **Removed from the plugin list:** PassiveTotal (1.0, PR #10: it never
  sent a request, and the API went to Microsoft with RiskIQ), and
  **Wayback, Bing and DuckDuckGo** (09-17, no recorded reason; their
  files remain). Ask the operator before re-adding any.

### 6.4 Prospeo (`api/prospeo.go`)

**Stock:** called endpoints Prospeo no longer has, could spend the whole
credit balance on one domain, and marked domains done when every call
failed.

**Hypermass (1.0, PR #6):** `GET /account-information` (free), then `POST
/search-person` filtered on the company website (25 per page, 1 credit per
paid page), then `POST /bulk-enrich-person` (50 per request, verified
emails only, 1 credit per email found). Spending is capped per domain by
`options:` on the Prospeo entry in `datasources.yaml`:
`max_emails_per_domain` (default 25; 0 turns it off) and
`min_remaining_credits` (default 0). A domain costs at most
`ceil(max/25) + max` credits. This added the generic data-source
`options:` map (integers only; `IntOption(name, default)`).

### 6.5 Domain WHOIS and RDAP (`whois/`)

**Stock:** port-43 WHOIS only; placeholder contacts skipped only for the
registrant; contact names became organizations.

**Hypermass:**
- **Domain RDAP first** (`whois/rdap.go`): the IANA bootstrap gives the
  TLD's RDAP server; the answer is mapped into the same structure WHOIS
  produces. Any RDAP error, including 404, falls back to port 43.
- **Answered** = a record stored, a WHOIS not-found/reserved/premium/
  blocked/other-domain reply, or an RDAP 404 whose WHOIS also found
  nothing.
- **Placeholders and privacy** (`privacy_detect.go`): placeholder
  contacts skipped in every role; detection of "On behalf of <domain>",
  "Registrant of <domain>", whoisproxy/domainsbyproxy text, identity-
  protection and masking phrases, privacy-service mail domains, and hashed
  mailboxes. Care-of addresses and role or placeholder names never become
  Locations or Organizations (section 7.7).

**Why:** many registries no longer answer port 43; privacy proxies and
placeholders were turning into organizations and addresses that pulled in
unrelated registrants (section 7.1).

**Impact of changing it:** RDAP does not follow the registry's link to the
registrar, so thin TLDs (.com/.net) may yield fewer contacts than port 43;
a failed bootstrap download disables domain RDAP until the engine restarts;
RDAP-derived contacts are tagged as WHOIS, and the domain RDAP source is
named `RDAP` like the network RDAP plugin's.

### 6.6 RDAP for networks and ASNs (`api/rdap/`)

RDAP registrations are how Hypermass decides who **owns** a netblock
(section 7.3), so their storage matters.

- **Answers vs failures:** `ObjectDoesNotExist`, `BootstrapNoMatch`,
  `BootstrapNotSupported` and `InputError` are answers; the rest are
  failures (6.1).
- **Registration storage (1.1, PRs #23, #24).** RDAP answers an announced
  /24 with the record that covers it, often a /22. Stock stored that
  record under the /24 with the /22's start and end; asset-db refuses a
  record whose CIDR does not contain its own range, the error was
  discarded, and the block was marked looked up. Every such block lost
  its record, contacts and ownership on every run (Fiserv's First Data
  blocks). Now `registeredPrefix` stores the record under the **largest
  CIDR inside the RDAP range that contains the block**; netblocks it
  covers share one record, each with its own `registration` edge. Within
  the 30-day TTL the record is found through that edge; a block marked
  with no record is queried again; an unstorable record is logged (`RDAP
  registration record not stored`, with the reason) and not marked.
- **Ownership checks:** linking a netblock re-runs the ownership check
  once per netblock per session, so a /24 linked after its siblings is
  still attributed; `admitParentNetblock` checks a record's ownership once
  before walking its (up to 256) linked netblocks.
- **Per-IP RDAP (1.1, IPAddress pos 5):** for routable IPs an in-scope
  name resolves to, query RDAP by address; keep answers more specific than
  the IP's BGP prefix (a block reassigned to the target inside a
  provider's aggregate) and store them as their own netblock and record.
  First shipped at position 41, which Port-Prefilter owns, and stopped the
  engine from starting (PR #22); `load_test.go` now catches that.
- **Contacts:** no Location for a care-of address, no Organization for a
  role, placeholder or care-of name.

**Impact of changing it:**
- Records are upserted by **handle** in asset-db, so a range stored under
  different blocks keeps whichever was written last.
- Answers that store nothing (404, no bootstrap match, a record missing
  either date, seen on AFRINIC and APNIC) are re-queried on every Netblock
  event.
- One 2 s limiter is shared by all three handlers.

### 6.7 BGP.Tools (`whois/bgptools/`)

Port-43 WHOIS to `bgp.tools` for each IP's announced prefix and ASN.
- **Hang fixed:** stock applied its 10 s timeout to the dial only; a
  server that accepted and went silent blocked `io.ReadAll` forever while
  holding the mutex every uncached IP needs (position 2 of the IPAddress
  pipeline), freezing the engine with nothing logged. The socket now gets
  the context deadline.
- **Serialization fixed:** the mutex was held across the network call,
  limiting lookups to 11 per minute engine-wide. It is now released around
  the query and the cache re-checked after.
- **No route is an answer (1.1, PR #27):** a `<nil>` prefix means no BGP
  route covers the address. It was logged as an error per address (896 of
  909 errors on one run). Now the address's /24 (/48) is recorded
  unrouted for the session, logged once, and its other addresses skip
  BGP.Tools, IP-Netblock's 30 s wait for a prefix, and port scanning
  (section 8.4).

### 6.8 GLEIF (`api/gleif/`)

Stock returned `(nil, nil)` for any non-200, which the fuzzy handler
stored as a **confidence-100 match**. Now a 404 or empty search is
`ErrGLEIFNotFound` (an answer) and other statuses are failures; the
related-organization handler marks only when both parent and children
requests completed. One 3 s limiter for all of GLEIF.

---

## 7. Scope: what the engine treats as the target's

The **scope** is the set of assets the engine treats as the target's:
in-scope names get subdomain OSINT, in-scope IPs get scanned and probed.
Hypermass changes both how scope grows and what stops it.

### 7.1 The problem

**Stock:** scope grew by **association** (section 2): shared registrant
organization, street address, certificate, an ASN's announced netblocks.
Two later fork features made any wrong addition expensive: runtime scope
domains get full subdomain OSINT (7.10), and every in-scope IP is port
scanned (4.1). One wrong link then cost tens of thousands of assets:

| Target | Wrong link | Result |
|---|---|---|
| vistra.com | one Cloudflare /24 → Cloudflare's organization → AS13335 → every announced block | ~500 CDN/cloud netblocks, ~58,000 "open" ports |
| crayon.co | Amazon Registrar's privacy-proxy street address, used by 19,000+ contact records | hundreds of unrelated organizations and domains |
| blue.cl | small Salesforce blocks its names resolve into; address variants of 415 Mission St; the role name "domain adminstrator" | Salesforce Marketing Cloud: 17 domains, two /16s, 18,000+ IPs |
| small companies | CDN/SaaS /24s admitted for any IP the pipeline touched (09-21 regression) | Cloudflare, Bitly, Stripe in scope; tens of thousands of names |

The design principle that came out of it: **expansion must not rest on
positive links alone.** Hypermass adds **deterministic, data-driven
evidence against** an asset belonging to the target, decides **netblock
ownership by registration**, and authorizes the target's hosts on shared
infrastructure **one IP at a time**, without admitting the provider's
space.

### 7.2 How assets enter scope now

| # | Path | Admits | Checks |
|---|---|---|---|
| 1 | Seeds (`scope.domains`, `ips`, `cidrs`, `asns`) | distance 0 | none; seeds exempt their own records from the foreign veto |
| 2 | Names under an in-scope domain | by suffix | — |
| 3 | Association (horizontals' FQDN/Organization/Location handlers, `Scope.IsAssociated`) | the associated asset | `-rigid` blocks; merged-certificate hook; role/placeholder and shared-address filters |
| 4 | Registration records (horizontals, pos 10) | the record's domain, AS, or linked netblocks | foreign veto (not for domains); hosting ≠ ownership; shared-ASN cap; `-rigid` blocks |
| 5 | Organization / Location walk | what each linked record registers | as 4; certificates: merged veto |
| 6 | TLS certificate handler | the CN's registered domain and organizations | merged veto; role filter |
| 7 | Resolution into a small netblock ("ambient") | — | **declined** in `enforce` (`VetoResolutionOnly`) |
| 8 | Ownership (RDAP contact email on a seed domain) | the netblock, **any size**; filled with `-active` | not subject to `scope_vetoes` |
| 9 | Provenance IP (DNS-IP) | the one IP an in-scope name resolves to | non-routable excluded; not subject to vetoes or `-rigid` |

Neighbour sweeps (DNS-IP's 25 addresses; horizontals' PTR sweep of 32, or
64 with `-active`) submit IPs for processing but do **not** add them to
scope. Scope only grows; the only removal is the domain blacklist.

### 7.3 Netblock ownership and the owned fill (`ip_netblock.go`, `whois/bgptools/netblock.go`, `support/owned_netblock.go`)

**Stock:** IP-Netblock and BGP.Tools stored each IP's netblock and AS but
**never added a netblock to scope**. A target's own address space that no
in-scope name pointed at was never scanned.

**Hypermass:**
- **Ambient admission (now vetoed).** The fork first added every
  discovered netblock (08-26), then gated it on "an in-scope name resolves
  here" plus a /20 size limit. A 09-21 change made the size check
  *replace* the name check, which admitted CDN blocks for small targets
  (fixed in 1.0, PR #9). Since 1.1 (PR #21) resolution alone never admits
  a block in `enforce` mode.
- **Ownership (`AdmitOwnedNetblock`).** A block is the target's when a
  contact of its RDAP registration (registrant, admin, abuse, technical)
  has an email on a seed domain or a subdomain of one. Fails closed on
  missing data. Owned blocks enter scope **at any size**, once per CIDR
  per session, logged as `netblock attributed to seed via RDAP contact`
  (`cidr`, `email`, `distance`). Called from BGP.Tools, IP-Netblock and
  the RDAP handlers (6.6); in practice the RDAP handlers decide, because
  the registration is fetched later than the netblock is created.
- **Owned fill.** With `-active`, an owned IPv4 block of /16 or smaller is
  **filled**: every usable address is created, linked and dispatched, so
  each passes the pre-filter itself. It starts when the block is
  attributed; `FinishOwnedNetblockFills` covers late attributions at
  session end (4.5). **Pacing (1.1, PR #29):** every 64 addresses the fill
  waits while the IPAddress backlog (queued + leased) is at 2,048 or more,
  so a /16 (65,534 addresses) no longer swamps the pipeline and the single
  database writer.

**Why:** finds the target's servers that have no DNS name, on space the
target provably registers, without trusting weak signals.

**Impact of changing it:**
- **Full fills are policy.** The operator wants thorough runs; do not cap
  below /16 without asking.
- The fill guard is process-wide, so a long-lived engine running several
  sessions never re-fills a block (section 17).
- Do not reintroduce resolution-based admission: it is how the CDN leaks
  happened. Run `scope_vetoes: observe` to see what it would admit.

### 7.4 Provenance authorization of single IPs (`dns/ip.go`)

When an in-scope name resolves to an IP, that exact address is added to
scope (`Scope().Add(ip)`), whatever its netblock. Non-routable addresses
are excluded. This is what lets the target's hosts on AWS, Cloudflare or
Salesforce be scanned without admitting the provider's blocks. It never
triggers a fill (fills key off scope netblocks only). An Info line
`provenance scan authorization: added IP to scope` marks each one; it was
meant to be temporary and is now the busiest log line (section 17).

**Impact of changing it:** HTTP-Probes' FQDN path depends on it for names
on third-party hosting (4.3); removing it silently drops those services.

### 7.5 Scope vetoes (`support/scope_decision.go`, `config/scope_vetoes.go`)

**Hypermass (1.1, Phase 1, PR #21):** a framework for evidence against.
- **Setting `scope_vetoes`:** `enforce` (default; also for an empty or
  unknown top-level value), `observe` (log `would decline`, keep the old
  behaviour), `off`. An unknown value under `options:` fails config
  loading.
- **`Decline(…)`** logs `scope decision` (`action`, `reason`, `type`,
  `asset`, evidence) once per session, reason and asset, and blocks only
  in `enforce`. Reasons: `VetoResolutionOnly`, `VetoForeignRegistrant`,
  `VetoMergedCertificate`, `VetoSharedASN`.
- **Only those four depend on the setting.** The shared-address, role
  and placeholder, care-of, hosting-is-not-ownership, ASN ≤ /20 and
  non-routable rules apply in every mode.
- **Provenance:** every horizontals addition logs `via`, `from` and
  `distance` from the seeds. **Recorded, not enforced** (planned for
  Phase 3).
- **State:** per-session maps are cleared by `ForgetSession`; process-wide
  verdict caches are keyed by database identity + entity ID
  (`entityCacheKey`), because entity IDs are unique only per database.

### 7.6 Registration verdict (`support/registration_verdict.go`)

For an IPNetRecord or AutnumRecord:
- **Owner:** a contact email on a seed domain (or subdomain), or the
  registrant organization already in scope.
- **Foreign:** a real registrant organization (not role, placeholder or
  care-of) that is not in scope **and** a contact email on a domain that
  is neither freemail (~55 providers) nor in scope.
- **No information:** everything else, including redacted records.

Owner beats foreign. Horizontals declines a foreign record where it would
admit what the record registers. Seeded CIDRs and ASNs are exempt.
**Known miss:** a target network registered under a parent company's email
domain reads as foreign (Mailchimp's networks name "MailChimp" with
intuit.com contacts). The "seed name match" fix is on hold by the
operator's decision.

### 7.7 Evidence filters

| Filter | Rule | Effect | Source |
|---|---|---|---|
| Care-of / mail drop (`support/care_of.go`) | `c/o`, `care of`, `PMB 255`, `#` + 5 or more digits | address not linked; counts as shared at once | registered agents |
| Role names (`support/role_names.go`) | every word from a role vocabulary ("Domain Administrator", "Hostmaster") | not an organization | blue.cl |
| Placeholders (`IsNonName`) | whole value: "N/A", "None", "Private Person", "Internet Widgits Pty Ltd", "MyCompany", … | not an organization | RU-CENTER registrants |
| Shared addresses (`support/shared_location.go`) | more than 25 records across every stored variant of the building | neither admitted nor walked; not used for org dedup | crayon.co, blue.cl |
| Merged certificates (`support/merged_cert.go`) | CNs across several registered domains, or several real subject organizations | not used as evidence anywhere | a serial-1 certificate linking 84 organizations |
| Privacy proxies (`whois/privacy_detect.go`) | section 6.5 | placeholder contacts skipped | crayon.co |

These are **vocabularies of language, not lists of companies**, which is
why they are acceptable under the "no static lists" policy (section 12).

### 7.8 Horizontals (`horizontals/`)

- Every addition is logged (`asset added to the session scope by
  horizontals`, with `via`, `from`, `distance`); stock added silently.
- **Hosting is not ownership (PR #19):** an in-scope netblock's
  registration expands to its registrant only when the block is owned
  (7.3); otherwise only on a registrant match. The target being a tenant
  of a provider's block does not make the provider part of the target.
- **Queue the FQDN (PR #20):** a domain admitted through its registration
  record is queued as an FQDN (stock queued the record, so the domain
  never got subdomain OSINT); a certificate adds its CN's registered
  domain (stock added the host CN, which added nothing).
- **ASN fan-out:** an AS announcing more than 500 netblocks is shared
  infrastructure (`VetoSharedASN`; 16 was tried first and caught American
  Express and Bank of America); under the cap only IPv4 blocks of /20 or
  smaller are admitted (stock admitted every block).
- Registration records find their netblocks through `registration` edges
  (up to 64), matching the storage in 6.6.

### 7.9 Session scope and organization dedup

- `sessions/scope`: `Add(TLSCertificate)` adds the CN's registered domain;
  a hook (`SkipAssociationEvidence`) lets `support` exclude merged
  certificates, because `scope` cannot import `support`. Matching is
  unchanged: domains by suffix, IPs by containment or exact, netblocks by
  exact CIDR, **organizations by exact case-insensitive name**, locations
  by building number + street + city + province.
- **Organization dedup** (`support/org/`): its ancestor walks were
  unbounded and exhausted memory (09-15, "Fix OOM condition"). They now
  follow only organization, id, subsidiary, registration and contact
  edges, at most 10 hops, 256 nodes, 32 same-name organizations, 2 s per
  walk; an aborted walk means "no match" (a duplicate organization rather
  than an unbounded merge). Shared addresses are never merge evidence.
  The global lock is held only for the final check and create.

### 7.10 FQDN OSINT bypass gate (`engine/registry/osint_bypass.go`)

**Stock:** every discovered name passed through the subdomain-OSINT
positions (20–40), whose shared positions are one-event-wide `Parallel`
stages. A scope domain held for tens of seconds in crt.sh blocked every
DNS-resolved name behind it.

**Hypermass (09-26, refined in 1.0):** a FIFO gate before position 20.
Exact configured domains and runtime scope domains (flagged by
Known-FQDN) take the OSINT path; every other name skips to the first stage
after 40 (HTTP probing). OSINT plugins ignored discovered names anyway, so
nothing is lost. A start-up check panics if a non-OSINT handler is ever
placed in 20–40, so it cannot be skipped silently.

**Impact of changing it:** this gate is an **amplifier**: any domain
admitted at runtime gets full subdomain OSINT, so scope admission must
stay strict. A new handler at positions 20–40 must be added to
`osintBypassSkippable` or the engine will not start.

### 7.11 Decisions and the remaining plan

Shipped fixes carry the letters used in discussion: A (privacy detection),
B and D (shared addresses), C (hosting ≠ ownership), E (role names), H
(placeholders), J (queue the FQDN), K (certificate CN domain), M (merged
certificates), N1 (care-of, masking), N2 (registration verdict, per-IP
RDAP, ASN cap 500). **G**, a curated provider-ASN list, was **shelved** by
policy. The operator chose **`enforce`** for Phase 1; ask before each new
phase whether it ships enforcing or observing.

Agreed but not built (full design in Appendix D; each must be tested against the leak chains **and**
legitimate expansion: a subsidiary, a brand domain on the target's
certificate, a block reassigned inside provider space, a seed with
redacted WHOIS):
- **Phase 2:** N3 (a domain an in-scope name delegates to by CNAME, NS,
  MX, SRV or SPF is a *vendor* and cannot be admitted by a weak link); N4
  (a PTR name in a foreign operator's domain means no neighbour sweep);
  sweep vetoes using both.
- **Phase 3:** a **seed fingerprint** built fresh each run from every seed
  (no root flag): registrant organizations, email domains, addresses,
  certificate organizations, GLEIF LEIs, self-hosted NS/MX, owned blocks,
  each passed through the 7.7 filters, grouped per acquisition, strong vs
  weak by element type. On top of it: distance limits (weak links only
  within one step of a seed), N5 (GLEIF LEI conflicts), N7 (a weak link to
  a different specific registrant is vetoed), NS/MX-host expansion, a
  revised shared-address exemption for the target's own busy HQ, and the
  seed name match (on hold).
- **Phase 4:** N6, fan-in/fan-out checks generalized to organizations,
  IPs, NS/MX hosts and email domains; a circuit breaker that stops any
  walk about to add more than ~25 new registered domains not tied to the
  fingerprint.

---

## 8. DNS

DNS is the engine's highest-volume activity. Hypermass makes resolvers
configurable and stops spending lookups on queries that cannot succeed.

### 8.1 Resolvers (`support/resolvers.go`)

**Stock:** a hard-coded list of public resolvers, an unlimited pool rate,
and a fixed wildcard-detection resolver (8.8.4.4).

**Hypermass (1.1, PR #16):** three environment variables, read once when
the engine starts, each falling back to stock behaviour:
- `AMASS_ENGINE_RESOLVERS`: comma-separated IPs, or a file with one per
  line (`#` comments), replacing the built-in list;
- `AMASS_ENGINE_RESOLVER_QPS`: an aggregate cap for the whole pool (0 or
  unset: no cap), for limits such as the AWS VPC resolver's per-interface
  ceiling;
- `AMASS_ENGINE_WILDCARD_RESOLVER`: the wildcard detector (default
  8.8.4.4).
A start-up line `trusted DNS resolvers: …` reports the choice.

**Why:** production engines in AWS must use their own resolvers without a
rebuild.

**Impact of changing it:**
- The built-in list (from upstream) includes **filtering** resolvers
  (AdGuard, CleanBrowsing, Quad9, Comodo, OpenDNS), which answer blocked
  names with a sinkhole or NXDOMAIN, and probably some dead ones. Use
  `AMASS_ENGINE_RESOLVERS` with unfiltered resolvers in production.
- The resolve library caps each nameserver at ~10 queries per second per
  record type. An unmerged branch would raise it for override lists
  (section 17).

### 8.2 Retries

`PerformQuery` makes at most **6** attempts (stock: 10). A usable answer,
NXDOMAIN, or "no record of this type" returns on the first reply; only
timeouts, refusals and useless replies used the extra attempts.
`ErrFailedMaxDNSAttempts` means all attempts errored.

### 8.3 Reverse names and dead zones (`dns/`, `support/reverse_dns.go`)

**Stock:** DNS-Reverse creates an FQDN for each address's `in-addr.arpa`
name and dispatches it, and the forward handlers then ran A/AAAA, CNAME
and TXT lookups on it: four lookups per address instead of one. Zones
that never answer were queried name by name, six attempts each.

**Hypermass (1.1, PRs #28, #29):**
- Forward handlers (DNS-IP, CNAME, TXT, Subdomains) skip `.arpa` names.
- **Broken reverse zones:** PTR outcomes are counted per /24 (IPv6 /48);
  after 5 failures with none answered, the network's other addresses are
  skipped for the session (`reverse DNS zone is not answering`).
- **Broken forward zones:** a zone is the name minus its first label,
  never the registered domain itself; after 10 distinct names fail with
  none answered, its other names are skipped (`DNS zone is not answering;
  forward lookups of its other names are skipped`).
- Any answer, including NXDOMAIN, keeps a zone open. All state is per
  session, so a zone that is fixed is tried again next run.

**Why:** on owned-block fills these were almost all the DNS failures:
17,897 of 18,007 on Blackbaud (reverse zones delegated to servers that do
not answer), 6,931 on the University at Buffalo (internal AD and wireless
zones delegated in public DNS).

**Impact of changing it:** a registered domain must never be capped (only
zones below it). Lowering the thresholds risks skipping a zone that is
only slow. A lookup that returns only a different record type is retried
and can count as a failure (rare).

### 8.4 Unrouted networks (`support/unrouted.go`)

BGP.Tools' no-route answer (6.7) marks the address's /24 (/48) as
unrouted for the session. BGP.Tools, IP-Netblock and the port pre-filter
skip such addresses (no probe can reach them). They are still filled and
still get reverse DNS, and are not marked as scanned, so a later session
checks the route again.

### 8.5 PTR attribution in owned blocks (`dns/reverse.go`)

When a PTR answer for an IP in a seed-owned block is an in-scope name,
DNS-Reverse also records `IP -ptr_record-> host` (next to the stock
two-hop chain through the `.arpa` name) and `apex -node-> host`, so domain
queries list names that have no forward record. Names that spell out the
address (`10-1-2-3.dhcp.example.com`) get no `node` edge, so a /16's
generic PTRs do not flood the subdomain list. Stock's PTR-triggered
neighbour sweep was removed (with DNS-IP's sweep reduced to 25 addresses
around in-scope names); since then only owned fills cover whole blocks.

---

## 9. Database and engine reliability

Large runs (100,000+ IPs, tens of hours) against a shared PostgreSQL
exposed hangs, deadlocks, lost writes and memory exhaustion that stock
Amass never hit on small runs. Each was root-caused, usually with pprof
goroutine dumps (MAINTAINERS 9.2).

### 9.1 asset-db facts that drive the design

asset-db **must not be modified, forked or patched**; Hypermass works
around it. Facts every change must respect:
- **One writer connection.** All writes go through a single PostgreSQL
  connection that batches queued writes from every caller into one
  transaction, with a savepoint per write, each run **under its caller's
  context**. It is the throughput ceiling of the whole engine.
- **Validation:** an IPNetRecord's CIDR must contain its start and end;
  records need their dates; natural keys are unique and case-insensitive
  (citext).
- `FindEntitiesByContent` returns an **error**, not an empty list, when
  nothing matches.
- The repository's `*sql.DB` has one connection and a 60 s
  `statement_timeout`.

### 9.2 The write guard (`engine/sessions/write_guard.go`)

**Problem (1.1, PR #26):** when a caller's timeout expired while its write
ran, the driver closed the writer connection to cancel it, and every
other write in the batch failed (`savepoint: conn closed`, `commit: conn
closed`). One plugin's short timeout dropped other plugins' writes.

**Hypermass:** the session wraps its repository. Every create and delete
runs under a context the caller cannot cancel, bounded at 5 minutes
(asset-db's batch limit). The caller still waits only as long as its own
context; if that ends first, it gets its error and the write completes in
the background (writes are idempotent upserts). A write whose caller has
already given up is not submitted. Reads pass straight through.
`Unwrap()` (1.2) returns the wrapped repository for code that needs its
concrete type.

**Impact of changing it:** **never type-assert `Session.DB()`**; unwrap
(section 4.5 shows what happened). Background write errors are invisible;
a write queued longer than 5 minutes still fails its batch.

### 9.3 Per-item store deadlines (`support/database.go`, `storeEach`)

**Problem (1.1, PR #25):** `StoreFQDNsWithSource` and
`StoreEmailsWithSource` gave a whole batch one 30 s deadline, so a large
answer stored its first 30 seconds and every later name failed. On one
run ~47,600 of IP-THC's names were dropped, and the lookup was still
marked.

**Hypermass:** each item gets its own 15 s deadline; storing stops when
the session ends; failures are logged once per batch (`failed to store
names`, with counts and the first error). `StoreFQDNsWithSourceCount`
reports the failures; IP-THC uses it to stay unmarked. About 25 sources
use these helpers; only IP-THC retries on failure so far.

### 9.4 Dispatcher: stranded leases and panics (`engine/registry/pipelines.go`)

**Problem:** a finished element was handed back to the dispatcher with a
non-blocking send; when the channel was full, it was dropped and never
Acked. With lease TTL 0 those rows stayed leased forever and the client
waited forever for idle (seen as `FQDN leased` stuck at 125).

**Hypermass:** if the send cannot happen, the backlog row is Acked
directly; a handler panic is recovered, recorded and Acked the same way.
`oam_enum` also gives up 2 minutes after the session-end hook is done if
work never goes idle (section 10.4). Lease TTL 0 is deliberate (a long
WHOIS or HTTP handler must not be reclaimed mid-flight). **Do not** Ack
every leased row at hook end: that would mark in-flight fill and sweep
IPs done.

### 9.5 Session semaphores and ScanSem (`engine/sessions/session.go`, `internal/net/network.go`)

- **Deadlock fixed:** stock held the session lock across a blocking
  semaphore acquire; release and resize need the same lock, so one
  goroutine waiting on a full semaphore froze everything.
- **ScanSem:** connect scans use their own semaphore (3,200 slots, one per
  session, never resized). NetSem (500 divided across sessions) bounds
  every other socket. Merging them would let a burst of probes contend
  with scan SYNs, or let scans starve plugins.
- `InUse()` and `Cap()` feed the dashboard.

### 9.6 Smaller fixes

- Byte-order marks in four Go files broke `go test -cover`; uploads
  through GitHub's web UI were the likely source (check new files with
  `head -c3`).
- Several handlers called `err.Error()` on a nil error (BGP.Tools,
  DNS-Reverse, the store helpers); fixed where found.
- A shadowed lease `ttl` variable in the backlog was renamed (no behaviour
  change; a test pins the never-reclaim mode).

---

## 10. Engine API, CLI and operations

### 10.1 New engine endpoints (`engine/api/server/`)

- `GET /api/v1/sessions/{token}/backlog`: per asset type `waiting`,
  `leased`, `queue`, `processed`, plus NetSem and ScanSem use and the
  pre-filter's scanned and open counts. Feeds the dashboard.
- `POST /sessions/{token}/end-work` (202) starts the session-end hook;
  `GET` returns its progress (section 4.5).
- `GET /api/v1/handler-stats`: per-handler average duration from
  InfluxDB. **Always 503**: no InfluxDB is deployed, by decision (it would
  add a production dependency for development-only value).

### 10.2 API fixes (1.1, PR #14)

- **Bulk asset add crashed the engine** on an asset the database refused
  (a nil entity dereferenced in a goroutine outside the HTTP server's
  recovery). Now the error is returned and each bulk goroutine recovers.
- The single-asset handler dropped the connection on the same panic; now
  500 with the reason, and 400 for an asset with no identifying value.
- A configuration without `scope` panicked; now 400 `scope is required`.
- Create-session refusals carry the reason in `details`, which the client
  shows.

### 10.3 Log stream (`engine/pubsub/logger.go`, `v1/websocket.go`)

**Stock:** a subscriber whose buffer filled cost one goroutine per message,
forever; there was no unsubscribe, and a departed WebSocket client stayed
subscribed (5,000 messages left 4,900 goroutines).

**Hypermass:** one queue and one pump goroutine per subscriber (the only
sender on its channel, which also closes it); `Unsubscribe`; the WebSocket
handler reads the connection and ends on disconnect or 60 s without a
pong. A slow but live client's queue is unbounded.

### 10.4 The `enum` CLI (`internal/enum/`)

- **Session end:** after 5 idle polls (2 s apart), or when the `-timeout`
  no-progress timer fires (default 30 min; 0 or less means 24 h), enum
  starts end-work, polls it, and exits when it is done and work is idle,
  or 2 minutes after done if work never goes idle (`stranded leases`).
  The log stream is read in its own goroutine (a busy stream starved the
  idle timer). Once end-work starts, enum resets its no-progress timer on
  every tick, so if the engine dies it waits until Ctrl-C.
- **`-scope-json`** (1.1, PR #18): just before terminating (also on Ctrl-C
  and with `-silent`) prints one line, `HYPERMASS_SCOPE {"session":…,
  "fqdn":[…],"netblock":[…],"autonomoussystem":[…],"ipaddress":[…]}`,
  sorted. A type that could not be read is listed under `errors`. Why:
  the scope lives only in engine memory and is gone when the session ends;
  the reports need it.
- **New flags:** `-active-proxy`, `-active-strict` (section 5),
  `-scope-json`. `-active`'s help text now says what it does.

### 10.5 Configuration and environment

| Setting | Where | Default | § |
|---|---|---|---|
| `active_proxy` | config, `options:`, `-active-proxy`, API JSON | none | 5 |
| `active_strict` | same, `-active-strict` | true (also for API JSON that omits it) | 5 |
| `scope_vetoes` | top level or `options:` | `enforce` | 7.5 |
| data source `options:` | `datasources.yaml`, per entry, integers | — | 6.4 |
| `AMASS_ENGINE_RESOLVERS`, `_RESOLVER_QPS`, `_WILDCARD_RESOLVER` | engine environment | built-in list, no cap, 8.8.4.4 | 8.1 |
| `nofile` 8192 | `compose.yaml` / pod spec | Docker 1024 | 4.1 |
| `HYPERMASS_TEST_POSTGRES_DSN` | test environment only | unset (test skipped) | 15 |

### 10.6 Start-up diagnostics

The engine logs `engine build info` (VCS revision, `vcs_modified`, and
the versions of wappalyzergo, resolve, asset-db and open-asset-model, read
from the binary), `trusted DNS resolvers: …` and `Recog fingerprints
loaded`. A missing revision means the Docker build context had no `.git`.
Why: "is this engine the code and dependencies I think it is?" cost real
time repeatedly before it existed.

### 10.7 Dependencies (`go.mod`)

- **Added:** `projectdiscovery/wappalyzergo` v0.3.11 (Tech-Stack; bumped
  v0.2.94 → 0.3.2 → 0.3.8 → 0.3.11, no API changes; its `headless`
  subpackage needs go-rod, which is not imported, so not linked);
  `runZeroInc/recog-go` (Protocol-Probes, fingerprints embedded);
  `golang.org/x/sync` (singleflight).
- **Moved with them:** `golang.org/x/net` (v0.62.0; `x/net/proxy` backs the
  SOCKS5 dialer, so re-run the active-egress tests after a bump) and the
  other `x/` modules.
- **Unchanged:** Go 1.26, asset-db v0.24.4 (must stay unmodified),
  open-asset-model, resolve.

### 10.8 Documentation and SQL functions

- `docs/engine_api.md` (1.1, PR #13): every endpoint for orchestrator
  authors, checked against a running engine. Note that `scope.cidrs` in
  JSON is Go's `net.IPNet` (`{"IP":…,"Mask":"<base64>"}`), not a string.
  Swagger (`docs/docs.go`, `swagger.yaml`) regenerated with swag v1.16.6.
- `docs/active_proxy_egress.md`: operator guide for section 5.
- `docs/hypermass_functions.sql`: the reporting functions, applied in one
  transaction (`CREATE OR REPLACE`; drop a function first if its result
  columns change). Each takes one comma-separated domain string:
  - `fqdn_by_domains`: every FQDN equal to or under the domains (uses
    `LIKE`, so `_` in a domain acts as a wildcard);
  - `ips_by_domains(domains, since, include_neighbors, max_cname_depth)`:
    one row per IP with reasons and evidence (`forward_dns`, `ptr`, `cert`,
    `owned_netblock`, optional `neighbor`);
  - `tplinks_by_domain`: third-party registered domains reached by
    NS/CNAME/MX/SRV records or page links, with evidence (needs
    `public.public_suffix_list`);
  - `other_domains_by_inscope_domains`: those third-party domains not in
    any company's `public.domains`;
  - `techstack_by_domains`: per host, service, ports, product, version and
    the plugin that identified it (VOLATILE: temp tables, so not on a
    read-only standby).
  - **Performance:** `fqdn_by_domains`, and every function built on it, is
    `PARALLEL UNSAFE`, so each call runs on a single core. Run many companies
    concurrently from separate connections rather than in one query.

### 10.9 Operator tooling (`utility/`)

Copies of what the operator runs from `~/amass-docker-compose`. **The
repository is public: every password and API key in these copies is
`CHANGE_ME`**, and the host copies hold the real values. Never commit real
ones.

- **`dashboard.py`**: live terminal view of the backlog buckets,
  NetSem/ScanSem, pre-filter counts and an end-work row per phase
  (`requeue (batch)` or `requeue (walk)`, progress, rate/min, ETC). Runs on
  the host (`sudo python3 utility/dashboard.py`) through `docker exec
  engine`. It copies four end-work limits from the engine as constants
  (500 requeues, 2 min, 15 min, 3 h); update them if the engine's change.
- **`enum-companies.py`**: runs enumerations one company at a time from
  `public.companies` and `public.domains`. Order: never enumerated first
  (by `run_schedule`: DAILY, WEEKLY, …), then oldest `last_enum`; NEVER or
  NULL schedules only when named on the command line. Passes the root
  domain first, then the rest, to `oam_enum -active -active-strict=false
  -silent -scope-json`, saves the scope line, and writes
  `./report/<id>-<name>.xlsx` (Assets, IP's, TP Links, Unknown Domains,
  Tech-Stack and four Scope tabs) from the SQL functions in 10.8. Stops
  the queue on any non-zero exit; Ctrl-C writes a partial report.
- **`report-enumerated.py`**: rewrites the report for every enumerated
  company, several at once.
- **`update-domains.py`**: syncs `public.companies` and `public.domains`
  from the company-domain CSV, with a preview and confirmation, in one
  transaction.
- **`config.yaml`, `datasources.yaml`**: the operator's Amass
  configuration (nmap top-100 ports, transformations and TTLs, data
  sources).

`domains.is_root` only orders the domain list; it has **no** scope meaning
(all seeds are equally authoritative).

---

# Part III — Working on Hypermass

## 11. Change-impact guide

The couplings that are not visible from one file. Before changing the
thing on the left, check the things on the right.

| If you change… | …check | Why (§) |
|---|---|---|
| A handler's position or add a handler | `load_test.go`; uniqueness of exclusive positions per asset type; positions 20–40 on FQDN (bypass allow-list); the order 41 → 42 → 43 on IPAddress | a clash stops the engine from starting; the bypass panics; probes read the pre-filter's output (4, 6.6, 7.10) |
| A handler's `Transforms` | that `IPAddress->ALL` / `FQDN->ALL` still enable it; that excluding a type still disables what it should | a handler with no matching transform never runs (4.1) |
| A plugin's source name | that no other plugin uses it | the source name is the TTL key; two plugins sharing it shadow each other (6.3) |
| What marks an asset done | the lookup-outcome rule | a failure marked as done hides the asset for the whole TTL (6.1) |
| Anything that writes to the database | the write guard; the single writer's throughput; timeouts (15 s per item, 5 min per write) | one caller's cancellation used to fail everyone's batch (9.1–9.3) |
| Code that needs the concrete repository type | `Unwrap()`, never a type assertion on `Session.DB()` | the sweep's batch was dead for three weeks (4.5) |
| Active network code | `ActiveDialer` / `ActiveHTTPClient` | anything else bypasses the proxy (5) |
| Port-scan concurrency or instance counts | `nofile` in `compose.yaml` and the pod spec; ScanSem's cap | at 1,024 FDs every plugin failed silently (4.1, 9.5) |
| Port pruning or `open_port` reads | write first, prune after, never after a cancelled scan; the `since` filter | false "open" or lost ports (4.1) |
| Scope admission (any path in 7.2) | that it cannot admit provider space on weak evidence; `observe` mode; the incident chains | the OSINT bypass and the pre-filter amplify every wrong admission (7.1, 7.10) |
| A veto | whether it should follow `scope_vetoes`; that it is logged once per session | only four vetoes are mode-dependent (7.5) |
| Process-wide caches | key by `entityCacheKey`; clear per-session state in `ForgetSession` | entity IDs are unique only per database (7.5) |
| RDAP storage | asset-db's CIDR validation; the `registration` edge lookup; upsert by handle | records were silently refused for months (6.6) |
| Relations between assets | `open-asset-model/relation.go` | unlisted labels are rejected silently (4.6) |
| Session-end work | that terminate, Ctrl-C and shutdown still do not run it; the dashboard's constants | stopping a run used to start hours of scanning (4.5, 10.9) |
| Owned fills | the backlog pacing; full fills are policy | a /16 swamped the writer (7.3) |
| DNS caps | that registered domains are never capped; that answers keep zones open | (8.3) |
| wappalyzergo, recog-go, `x/net` | exported API; Angular in the static path; active-egress tests | (4.6, 10.7) |
| Configuration fields | `UnmarshalJSON` defaults for API sessions; Swagger; `engine_api.md` | `active_strict` must default to true over the API (5, 10.8) |
| The SQL functions | dependent reports; `CREATE OR REPLACE` limits; hard-coded type ids in `tplinks_by_domain` and `techstack_by_domains` | (10.8) |
| A file under `utility/` | secrets back to `CHANGE_ME` before committing | the repository is public (10.9) |

---

## 12. Policies and constraints

Standing instructions from the operator. Treat them as rules.

**Never**
- commit to `service-detection`;
- delete or "clean up" database data. "Everything in the database is
  valuable. There is no bloat to prune." Do not write fixes for old data
  in the development database (production starts fresh);
- modify, fork, patch or send changes upstream to **asset-db** (and treat
  other upstream modules the same unless told otherwise); work around them
  in Hypermass;
- put credentials (the database password, API keys) into commands,
  commits, files in the repository or messages. The repository is public;
- run anything against the engine or database that writes, when
  diagnosing. Diagnostics are read-only;
- put a model name or ID in code, comments, docs, commits or PR text,
  beyond the attribution trailers the session specifies.

**Design**
- **No static lists of companies or providers.** "Static lists don't hold
  up over time." Derive signals from data (registration, ownership, fan-in
  counts). Vocabularies of words (role words, freemail domains, care-of
  patterns) are acceptable.
- **Deterministic and data-driven**: explain every rule with the record
  that justifies it.
- **Thorough by default.** Admitting wrong assets is worse than missing
  right ones, but missed expansion is still a cost. Owned-block fills stay
  full.
- **All seeds are equally authoritative.** No root-domain flag in scope
  logic; fingerprints and veto state are built fresh each run, never
  stored.
- Re-checking candidates declined earlier in a run was proposed and not
  wanted; a later run picks them up.

**Working style**
- Give the operator **commands, not scripts** for diagnostics, and say what
  each result would mean before they run it.
- **Database queries must be efficient**: the database is large and shared
  with running enumerations (section 14.3).
- The operator runs SQL in **pgAdmin 4 on Windows**, not `psql` on the
  host: no `\o`, no host paths; results are saved with "Save results to
  file"; set `client_encoding = 'UTF8'` if a WIN1252 error appears.
- Lead with the finding, then the evidence, then the proposal. Correct
  earlier mistakes plainly when the data shows them.

---

## 13. How work is delivered

1. **Investigate** with commands the operator runs (section 14); read the
   real source of any dependency involved (asset-db, open-asset-model,
   resolve, openrdap) rather than reasoning about it.
2. **Propose** the fix with the evidence and wait for a go-ahead unless
   the operator already asked for it.
3. **Build** on a branch from the current `origin/hypermass-1.2`:
   - tests that **fail on the old code** and pass with the fix (check by
     temporarily restoring the old code);
   - `go build ./engine/... ./config/...`, `go vet` and `gofmt -l` on
     changed packages, `go test ./engine/... ./config/...`;
   - update `MAINTAINERS.md`, this briefing and `CHANGELOG.md`.
4. **Commit** one commit per change, author `Claude
   <noreply@anthropic.com>`, ending with the session's attribution
   trailers.
5. **Deliver**, one of two ways depending on the session:
   - **With GitHub access** (since 1.2, when the operator asks): push the
     branch, open a PR into `hypermass-1.2` (merge commit, as for every PR
     so far), merge it when asked, then verify;
   - **Without it:** send a patch (`git format-patch`) verified with `git
     am` on a clean checkout of the base, plus an apply block that checks
     the base hash, and a compare link
     (`…/compare/hypermass-1.2...<branch>?expand=1`).
6. **Verify after merge:** the branch's tree equals the tested commit's
   tree, and `service-detection` is still `176be5e5`.
7. **Rebuild** for engine changes, after any running enumeration finishes:
   `sudo docker compose build --no-cache engine enum` and `sudo docker
   compose up -d --force-recreate engine`. Changes to `docs/` or
   `utility/` need no rebuild.
8. **Verify on the next run** with a diagnostic block (section 14).

---

## 14. Diagnostics

### 14.1 Logs

On the host, `~/amass-docker-compose/logs/amass/`: `engine/<date>-amass-
engine.log` (one per UTC day, every session) and `enum/<date>-enum-<id>.log`
(one per run).
- **Filter by session ID**, not by time window: `find -mmin` selects whole
  files, and the engine file holds every session of the day.
- Session-logger lines carry `session=<uuid>`; plugin-logger lines
  (`lookup failed; not marked…`, `IP-THC CSV …`, `Plugin started`) do not;
  filter those by timestamp.
- Fields in `[...]` print alphabetically (`asset=` opens the bracket as
  `[asset=`); grouped fields print with their group prefix
  (`plugin.failed_chunks=1`); values with spaces are quoted.
- Use `LC_ALL=C sort` before `comm`/`uniq`. Timestamps are UTC; the
  dashboard clock is local.

A starting block:
```bash
cd ~/amass-docker-compose
L=$(find logs/amass -name '*.log' -mmin -900)
S=session=<session id>
M() { grep -h -F "$S" $L; }
M | grep -E '\[(WARN|ERROR)\]' | sed -E 's/^[^ ]+ [^ ]+ (\[[A-Z]+\] [^[]*) \[.*/\1/' \
  | cut -c1-110 | LC_ALL=C sort | uniq -c | sort -rn | head -12
M | grep 'scope decision' | grep -o 'reason="[^"]*"' | LC_ALL=C sort | uniq -c | sort -rn
M | grep 'netblock attributed to seed via RDAP contact' | grep -oE 'cidr=[^ ]*|email=[^ ]*' | paste - - | LC_ALL=C sort -u
M | grep -F 'miss-list query' | cut -c1-300
```

Lines worth knowing: `scope decision`, `netblock attributed to seed via
RDAP contact`, `asset added to the session scope by horizontals`,
`skipping location/organization: …`, `RDAP registration record not
stored`, `failed to store names`, `no BGP route covers the network`,
`reverse DNS zone is not answering`, `DNS zone is not answering`,
`owned-netblock fill paused/finished`, `batch miss-list query`, `batched
miss-list query not available`, `lookup failed; not marked`.

### 14.2 The engine

- `utility/dashboard.py` for live state (10.9). `waiting` = backlog
  queued, `leased` = claimed, not yet Acked, `queue` = pipeline queue.
- pprof on `127.0.0.1:6060` inside the engine container
  (`docker exec engine wget -qO- 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=1'`,
  wrapped in `timeout 8`). It has resolved more problems on this project
  than any other tool.
- `sudo docker stats --no-stream` for CPU and memory.
- The API is not published on the host (port 4000 is internal); reach it
  through `docker exec engine wget` or the container IP.

### 14.3 SQL (pgAdmin, read-only, efficient)

- Start with `SET statement_timeout = '60s';`.
- Indexed equality only. Useful indexes: `ipnetrecord.handle` and
  `record_cidr` (unique), `netblock.netblock_cidr` (unique), `entity
  (table_name, row_id)`, `edge (from_entity_id)`, `edge (to_entity_id)`,
  `entity_tag (entity_id)`, `organization.org_name`.
- **Never** range tests (`record_cidr >>= block`) or `LIKE` on big tables;
  one such query ran past ten minutes and was killed. To find records
  covering a block, enumerate supernets (`set_masklen(b, n)` over
  `generate_series(8, 24)`) and join by equality.
- Force small steps with `MATERIALIZED` CTEs and `LATERAL`.
- `entity.table_name` values look like `'public.netblock'`; an
  `ipnetrecord` may sit under a larger CIDR than its netblock (6.6), so
  find it through the netblock's `registration` edge; `last_monitored`
  tags show what ran and when.

### 14.4 Checking the outside world from the assistant's sandbox

Outbound HTTPS only: no DNS port, no WHOIS port 43, no access to the
operator's database. Use RDAP over HTTPS (`rdap.arin.net`,
`rdap.apnic.net`, `rdap.db.ripe.net`), RIPEstat for BGP visibility, and
Google DNS-over-HTTPS (`dns.google/resolve`) for DNS.

---

## 15. Building and testing

- Go 1.26. `go build ./...` fails outside Docker (`internal/libpostal`
  needs the C library); build and test `./engine/... ./config/...`.
- `engine/plugins/load_test.go` starts every plugin against a real
  registry; run it after adding or moving a handler.
- Most tests use SQLite asset databases in `t.TempDir()`. SQLite and
  PostgreSQL share validation, so most storage bugs reproduce on SQLite,
  but the single batching writer and the sweep's batched query exist only
  on PostgreSQL.
- **PostgreSQL tests:** set `HYPERMASS_TEST_POSTGRES_DSN` to a scratch
  database URL with no query string (`postgres://user:pass@host:5432/db`);
  asset-db creates its schema there. `TestSweepBatchedAgainstPostgres`
  uses it and is skipped otherwise. A throwaway local cluster works
  (`initdb` + `pg_ctl` as the `postgres` user; listen on TCP if the socket
  path is too long).
- Per-package fakes exist; reuse them: `support` (`newP1Session`,
  `fillSession`, `scanSession`), `api/rdap` (`newRDAPTest` with a fake RDAP
  server), `horizontals` (`ownerTestSession`), `api` (`newMarkTestEvent`),
  `dns` (`newReverseTest`), `whois/bgptools` (a fake WHOIS server),
  `sessions` (`fakeRepo`), `protocol_probes` (`sweepTestSession`,
  `fullSweepSession`, `wrappedRepo`).
- Pitfalls: documentation ranges (`192.0.2.0/24`) are reserved, so
  handlers that skip reserved addresses return early and a test passes for
  the wrong reason (use a public address); handlers need transformation
  TTLs in the test config to get past their first check; grouped log
  fields print with a prefix (`plugin.`).

---

## 16. Things that are easy to get wrong

- **Verify against the real source** before relying on behaviour; every
  wrong assumption in this project's history came from reasoning instead
  of reading or measuring.
- A **decision made after an asset passed its consumer has no effect**
  unless something re-examines it.
- **Scope only grows.** There is no removal except the domain blacklist.
- The `scope` package cannot import `support`; it exposes hooks that
  `support` sets in `init()`.
- **Organizations match by name**, and many entities share a name; key
  anything per organization by normalized name.
- RDAP answers can be larger than, smaller than or misaligned with the
  queried prefix, and registries differ.
- A log line that can repeat per address (fills dispatch whole /24s) must
  be once per session or once per network.
- Commands for the operator must work on their host as typed: test regexes
  against the real log format, and say what an empty result means.
- Files uploaded through GitHub's web UI may carry byte-order marks, CRLF
  line endings or an executable bit.

---

## 17. Known issues and open work

**Suspected defects** (found by reading the code; not confirmed on a run;
ask before fixing):
- HTTP-Probes' banner pre-peek passes a nil dialer and never sees a banner
  (4.3).
- A proxy outage mid-run can prune an IP's stored ports (4.1).
- SOCKS5 CONNECT waits are bounded only by the session context (5).
- Process-lifetime dedups: the owned-fill guard, IP-THC's /24 dedup and
  CommonCrawl's collection cache outlive the session (6.2, 7.3).
- `ForgetSession` runs only on the end-work path (4.5).
- enum waits forever if the engine dies during end-work (10.4).
- Netblock RDAP re-queries answers that store nothing (6.6).

**Known gaps:** RDAP records with only one event date are not stored;
domain WHOIS is attempted on hostnames that are not registered domains;
`unspecified IP addresses are not allowed` and empty location city or
country errors appear a few times per run (untraced); only IP-THC retries
after store failures; the temporary `provenance scan authorization` line;
decoys are not logged; several sources still mark every lookup (6.1).

**Where MAINTAINERS disagrees with the code** (prefer the code; it has not
been corrected): stock IP-Netblock/BGP.Tools never admitted netblocks (it
says they did); stock's PTR sweep did fire for seeded CIDRs and addresses;
the horizontals PTR sweep still exists; Recog databases are chosen by
banner classification, not port, and SSH matches the software field;
there is no separate cloud-mailbox check in ownership; DNSHistory and
SiteDossier fail silently and still mark; `engine_api.md` gives the wrong
`-timeout` default (it is 30 minutes) and says the resolver variables are
read only by the CLI (the engine reads them).

**Planned:** scope Phases 2–4 (7.11); release tags for 1.1 and 1.2 when
the operator decides (notes from `CHANGELOG.md`).

**Unmerged work** (lived only on an earlier clone of the assistant's; ask
before reviving): `feat/resolver-per-ns-ceiling` (raises the resolve
library's per-nameserver ceiling for override lists); `feature/source-check`
(`oam_sourcecheck`, a probe of every configured data source); the shelved
provider-ASN list (policy says no).

---

# Appendices

## A. Pipeline positions touched by the fork

| Pipeline | Pos | Handlers |
|---|---|---|
| FQDN | 2, 3, 7, 8, 9 | DNS-CNAME, DNS-IP, DNS-Subdomains, DNS-Apex, DNS-TXT |
| FQDN | 10 / 11 | Horizontals / Known-FQDN |
| FQDN | 14 | WHOIS-FQDN (domain RDAP, then port 43) |
| FQDN | gate | OSINT bypass, before the first position ≥ 20 |
| FQDN | 22 | AlienVault, CertSpotter, crt.sh |
| FQDN | 23 | DNSRepo |
| FQDN | 25 | SubdomainCenter, HackerTarget, DNSDumpster, URLScan, CommonCrawl, IP-THC |
| FQDN | 29 | Prospeo |
| FQDN | 34, 36, 37 | DNSHistory, RapidDNS, SiteDossier |
| FQDN | 41 | HTTP-Probes (FQDN) |
| IPAddress | 2 / 4 / 5 | BGP.Tools / IP-Netblock / RDAP per-IP |
| IPAddress | 8 / 10 | DNS-Reverse / Horizontals |
| IPAddress | 22 | IP-THC |
| IPAddress | 41 / 42 / 43 | Port-Prefilter / HTTP-Probes (IP) / Protocol-Probes |
| Service | 10 / 42 / 43 / 44 | Service-Banner-URLs (stock) / JARM / Page-Links / Tech-Stack |
| Netblock | 2 / 40 | BGP.Tools AS / RDAP |
| IPNetRecord, AutnumRecord, DomainRecord | 2 | RDAP, RDAP, WHOIS record handlers |
| Organization, Identifier | 48 | GLEIF |

## B. Constants

| Constant | Value | Where | § |
|---|---|---|---|
| `maxConcurrentPortsPerIP` | 100 | `support/portscan.go` | 4.1 |
| `PortPrefilterScanTimeout` | 2 s | `support/portscan.go` | 4.1 |
| `MaxScanConns` (ScanSem) | 3,200 | `internal/net/network.go` | 9.5 |
| `LikelyDecoyThreshold` / `DecoyTimeBudget` | 50 / 90 s | `support/portpriority.go` | 4.2 |
| `PeekTimeout` | 2 s | `protocol_probes` | 4.4 |
| `sweepMaxResubmit` | 500 | `protocol_probes/sweep.go` | 4.5 |
| `sweepIdleTimeout` / `sweepDrainWait` | 2 min / 15 min | `protocol_probes/sweep.go` | 4.5 |
| `missListChunk` / `maxConsecutiveChunkFailures` | 5,000 / 3 | `protocol_probes/sweep_query.go` | 4.5 |
| `ownedMinPrefixBits` | 16 | `support/owned_netblock.go` | 7.3 |
| `ownedFillMaxBacklog` / `ownedFillCheckEvery` | 2,048 / 64 | `support/owned_netblock.go` | 7.3 |
| `maxAnnouncedNetblocksForScope` | 500 | `horizontals` | 7.8 |
| `MaxRecordsPerLocation` | 25 | `support/shared_location.go` | 7.7 |
| `BrokenReverseZoneFailures` / `BrokenForwardZoneNames` | 5 / 10 | `support/reverse_dns.go` | 8.3 |
| DNS attempts | 6 | `support/resolvers.go` | 8.2 |
| `storeItemTimeout` | 15 s | `support/database.go` | 9.3 |
| `detachedWriteTimeout` | 5 min | `sessions/write_guard.go` | 9.2 |
| Proxy dial timeout | 6 s | `internal/net/active_egress.go` | 5 |

## C. Incident history

| Target | What happened | Fix (§) |
|---|---|---|
| a large public university | 48 h runs probing closed ports | port pre-filter (4.1) |
| (every run) | JARM produced zero fingerprints | 4.7 |
| (fleet) | URLScan dark for weeks, then IP-blocked; sources marked failures as done | User-Agent, lookup rule (6.1, 6.2) |
| small companies | CDN /24s admitted, tens of thousands of names | netblock gate (7.3) |
| vistra.com | ASN fan-out into ~500 CDN netblocks | shared-ASN cap (7.8) |
| crayon.co | privacy-proxy address pulled in hundreds of registrants | privacy detection, shared addresses (7.7) |
| blue.cl | grew into Salesforce Marketing Cloud | hosting ≠ ownership, address variants, role names, registration verdict (7.6–7.8) |
| Fiserv | First Data blocks never attributed (RDAP records refused) | registration storage (6.6) |
| Mailchimp | ~47,600 names dropped by a shared deadline; own networks read as foreign | per-item deadlines (9.3); seed name match on hold (7.6) |
| Blackbaud | batches killed by callers' timeouts; 896 BGP.Tools `<nil>` errors; 17,897 reverse failures | write guard, unrouted networks, reverse caps (9.2, 6.7, 8.3) |
| University at Buffalo | internal zones' forward failures; a /16 fill saturated the writer | forward cap, fill pacing (8.3, 7.3) |
| Truist | repeat target: Known-FQDN replays every stored name, backlog fills at start | expected; fills wait (7.3) |
| (a 113k-IP run) | session-end sweep walked every IP for hours | batched query restored (4.5) |

## D. Scope plan: the agreed design in full

The detailed design behind section 7.11, as agreed with the operator.
Section 7 describes what shipped; this appendix is the reference for
building Phases 2–4. "Shipped" rows match section 7.

### D.1 What already shipped (mapped to the names used in discussion)

Lettered fixes from the scope reviews, and the "N" negatives from the veto
design. MAINTAINERS 13.4 has the details.

| Name | What | Status |
|---|---|---|
| A | Privacy/proxy detection in WHOIS | shipped (PR #17) |
| B | Shared-address cap (> 25 records) | shipped (PR #17) |
| C | Hosting is not ownership (in-scope netblock expands registrant only if owned) | shipped (PR #19) |
| D | Shared-address cap counts every variant of the building | shipped (PR #19) |
| E | Role names are not organizations | shipped (PR #19) |
| F | Organization-diversity check on addresses | **revised F** deferred to Phase 3 (below) |
| G | Curated provider-ASN list | **shelved** (static list) |
| H | Placeholder names (N/A, Private Person, Widgits…) | shipped (PR #20) |
| J | Queue the FQDN, not the DomainRecord | shipped (PR #20) |
| K | Certificates add their CN's registered domain | shipped (PR #20) |
| M | Merged certificates | shipped (Phase 1, PR #21) |
| N1 | Explicit statements: care-of, mail drops, masking | shipped (Phase 1) |
| N2 | Registration verdict; resolution no longer admits; per-IP RDAP; ASN backstop 500 | shipped (Phase 1) |
| — | Shared-provider ASN fan-out | shipped (PR #15, revised in Phase 1) |

### D.2 Phase 1 settings chosen by the operator

- `scope_vetoes` default **`enforce`** (the operator chose enforce over
  observe for Phase 1). Ask again before each new phase whether it ships
  enforcing or observing.
- Provenance (`via`, `from`, `distance`) is logged but **not enforced**.

### D.3 The decision points

Every veto applies at one of these places:

| # | Where scope grows | Code |
|---|---|---|
| D1 | Horizontals adds an asset | `addToScopeAndEnqueue` (all horizontals additions) |
| D2 | Horizontals starts walking a pivot | `horOrg` / `horLocation` `processInScope` → `expandFromContactRecord` |
| D3 | Association adds an asset | `scope.IsAssociated` (hook from support; scope cannot import support) |
| D4 | A netblock or ASN is admitted | `ip_netblock.go`, `bgptools/netblock.go`, `AdmitOwnedNetblock`, horizontals record handler, `addASNetblocksToScope` |
| D5 | Neighbours are swept | `dns/ip.go` (25 around each IP), `horizontals` IP handler (32, or 64 with `-active`) |
| D6 | WHOIS, RDAP and certificate data are stored | contact storage in `whois/`, `api/rdap/`, `enrich/tls_cert.go` |

Verdicts are **owner** (strong or weak), **foreign** (with a reason), or
**no information**.

### D.4 The seed fingerprint (Phase 3's foundation) — agreed design

The distinction that matters is **seed data versus data from expansion**:
seeds are vouched for by the operator; mid-run additions are the engine's
guesses. A fingerprint built only from seeds cannot drift.

- **Built from every seed**, no root flag. Elements: the seed domains;
  registrant organizations, registrant email domains, registrant addresses
  (each seed's WHOIS/RDAP); certificate subject organizations on seed
  hosts; GLEIF LEIs for those organizations; self-hosted name and mail
  servers (NS/MX under a seed domain); netblocks and ASNs N2 judges owned.
- **Every element passes the no-information filters first**: proxy and
  placeholder detection (A, H), role names (E), care-of (N1), shared
  addresses (B/D), freemail, fan-in (N6). An acquired startup at a
  coworking address contributes its organization and email domain, not the
  address.
- **Groups, not one identity.** Seeds that share elements form a group
  (usually the core company); each unlinked acquisition forms its own. **No
  group is privileged**, because every seed is vouched for. No warning
  about seeds that share nothing (it would fire on every acquisition).
- **Strength by element type, not by group.** Strong: contact email on the
  seed's own domain; GLEIF LEI; certificate subject organization on the
  seed's own host; self-hosted name servers under a seed domain. Weak:
  registrant address; organization name with no LEI. Weak elements support
  only weak links within one step of a seed.
- **No readiness wait.** Use the fingerprint incrementally from the first
  event. An incomplete fingerprint only makes the engine stricter (fewer
  strong links, fewer exemptions), which errs in the safe direction.
- **Lookups are sets** (normalized org names, email domains, LEIs, NS/MX
  hosts, address keys); constant time per decision, fine for 100+ seeds.
- **Built fresh per run**; not persisted.
- An empty fingerprint (all WHOIS redacted) leaves the engine as today
  plus the negatives that need no fingerprint.

### D.5 Remaining phases

**Phase 2** (no fingerprint needed)
- **N3 — delegation to a vendor.** When an in-scope name points (CNAME,
  NS, MX, SRV) at a registered domain not in scope, record that domain as
  a vendor. Parse SPF (`include:`, `redirect=`, `a:`/`mx:` domains) and
  DKIM selector CNAMEs the same way. Uses: a vendor domain cannot be
  admitted through a **weak** link (address, org-name match, association);
  strong evidence still admits it. A vendor already in scope whose own
  registrant is a specific other organization gets blacklisted (strong
  negative only; the blacklist is the only "undo" scope has, and only for
  domains). IPs reached only through a CNAME into a vendor get no sweep and
  no netblock admission. Walk-through: blue.cl's `click.blue.cl` CNAMEs into
  exacttarget.com and its SPF includes Salesforce, so both are vendors
  before the WHOIS walk would try to add them.
- **N4 — reverse DNS naming a foreign operator.** An IP whose PTR name's
  registered domain is not in scope, not linked to the target, and is a
  vendor, or registered to a specific other organization, or used across
  many unrelated netblocks (N6) is foreign-operated: no neighbour sweep
  (D5); a netblock whose PTR names are mostly foreign-operated is foreign
  (backup to N2 when RDAP is missing). **Never** used against the target's
  own named IP. Infrastructure domains (Google's `1e100.net`) count as
  linked when registered to an in-scope organization.
- **Sweep vetoes** (D5) using N3/N4.

**Phase 3** (the fingerprint)
- Seed fingerprint (D.4).
- **Distance limits**: weak pivots may admit only within one step of a
  seed; further needs strong evidence. Both big leak chains were three or
  more weak steps.
- **N5 — GLEIF.** Negative: an organization matched by name whose LEI
  differs from the matching in-scope organization's LEI is not a match
  (either side missing an LEI → name match stands). Positive: GLEIF parent
  or child of a fingerprint LEI is a strong link, one level only, probably
  opt-in (conglomerates).
- **N7 — different specific registrant, weak links only.** If a D1
  admission rests on a weak link and the candidate's registrant is a
  specific, non-placeholder organization not in the fingerprint, veto.
  Strong links (seed-domain email, fingerprint org with no LEI conflict,
  SAN on a certificate whose subject is a fingerprint org, GLEIF link, same
  registrant email domain) are unaffected.
- **NS/MX-host expansion**: zones served by the fingerprint's self-hosted
  name and mail servers become a way to find the target's other domains,
  with the NS/MX fan-in check so a hosting company's customers aren't
  swept in. Works with redacted WHOIS.
- **Revised F**: the shared-address check counts records as now, but an
  address with **5 or fewer real organizations, including an in-scope or
  fingerprint organization**, is exempt (the target's own busy HQ).
- The **seed name match** proposal (MAINTAINERS 13.10, Mailchimp) fits
  here as a fingerprint element: a registrant whose normalized name
  (lowercase, leading "the" and trailing legal forms removed, punctuation
  removed) equals a seed's label or whole registered domain without dots.
  The operator put it on hold; raise it when Phase 3 starts.

**Phase 4**
- **N6 — fan-in and fan-out, generalized** as one `PivotIsShared(pivot)`:

  | Pivot | Counts | Shared when | Exemption |
  |---|---|---|---|
  | Address | records | > 25 (as now) | revised F |
  | Organization | distinct registered domains via its contacts | > 25 | fingerprint org (if it doesn't itself fan out) |
  | IP | distinct registered domains with A/AAAA to it | > 10 | none |
  | NS/MX host | distinct zones using it | > 25 | none |
  | Contact email domain | distinct registrants | > 25 | fingerprint email domains |
  | Certificate | merged (M) | always | none |

- **Circuit breaker at D2**: before walking a pivot, count how many new
  registered domains the walk would add; more than ~25 and not tied to the
  fingerprint → stop, mark shared, log. Works on an empty database.

Every phase is tested against the leak chains (crayon.co, blue.cl) **and**
legitimate expansions (a subsidiary, a brand domain on the target's own
certificate, a target block reassigned inside provider space, Google's HQ,
a seed with redacted WHOIS).
