# Hypermass — Development Briefing

A hand-off document for an AI assistant (or a developer) continuing work on
Hypermass. It records what the code does not: how the work is done, the
environment it runs in, the decisions already made, the agreed plan, and
what was learned the hard way. Read it together with `docs/MAINTAINERS.md`,
which documents the code itself (Parts 1–12 up to release 1.0, Part 13 for
`hypermass-1.1`).

State as of `hypermass-1.1` at `e521102b` (PR #29, 2026-11-03).

---

## 1. What Hypermass is

- A fork of **OWASP Amass v5** (the engine, `oam_enum` client and plugins),
  maintained at **`github.com/prisoner881/hypermass`** (renamed from
  `prisoner881/amass`). The Go module path is still
  `github.com/owasp-amass/amass/v5`; binaries and banner strings were not
  rebranded (MAINTAINERS Part 12).
- Used by **FortifyData** for external attack-surface enumeration of client
  organizations. The work is authorized. Enumerations are **thorough by
  policy**: the operator would rather spend time than miss assets.
- Production runs 30–50 isolated engines on AWS EKS against a shared
  PostgreSQL 17 behind pgBouncer, driven through the engine API rather
  than `oam_enum` (MAINTAINERS Appendix C). Development and testing happen
  on the operator's single host.
- The fork's main additions: port pre-filtering and service detection
  (1.0), active-egress proxying, an engine API reference, and a large
  overhaul of how scope grows (1.1).

### The core problem being worked on

Amass grows the **scope** (the set of assets treated as the target's)
during a run by association: registrant organizations, street addresses,
certificates, netblocks, ASNs. Unchecked, one wrong link (a privacy-proxy
address, a CDN netblock, a registrar's role name) pulls in thousands of
unrelated assets, which then get port-scanned. Most of 1.1 is about
**stopping improper scope expansion with deterministic, data-driven
negative evidence** while keeping legitimate expansion. Section 6 is the
agreed design.

---

## 2. People and roles

- **The operator / maintainer** (GitHub `prisoner881`): owns the
  repository, runs every enumeration, applies every patch, creates and
  merges every PR. All decisions are theirs. They read diffs, push back on
  weak reasoning, and expect findings backed by data.
- **Keith** drives the engine directly through its API (no `oam_enum`, no
  `enum-companies.py`), as production does. Any design must work for an
  engine-only caller with nothing but the session config.
- **You** (the assistant): investigate, design, write code and tests,
  produce patches, write diagnostic commands for the operator to run. You
  cannot reach the operator's host, database or logs directly; everything
  you learn about a run comes from output they paste.

---

## 3. Repository, branches and clones

| Item | Value |
|---|---|
| GitHub | `prisoner881/hypermass` |
| Active branch | **`hypermass-1.1`** (all new work targets it) |
| Frozen branch | **`service-detection`** at **`176be5e5`** — release 1.0 plus the MAINTAINERS upload. **Never commit to it, never touch it.** Verify it after every merge. |
| Release tag | `hypermass-v1.0.0` (`5041be70`). 1.1 is untagged. |
| Operator's clone | `~/hypermass` on the host |
| Compose directory | `~/amass-docker-compose` on the host (where `compose.yaml`, `config/`, `logs/`, the operator scripts and `report/` live) |

**Unmerged local work** (exists only on the assistant's previous clone; do
not assume it is anywhere):
- `feat/resolver-per-ns-ceiling` (`4306bcc0`): raises the resolve
  library's ~10 qps per-nameserver ceiling for operator resolver lists
  (MAINTAINERS 13.3). Built and tested, never applied.
- `feature/source-check` (`7a8e3454`): `oam_sourcecheck`, a tool that
  sends one request to every configured data source and reports which
  work. Never applied.
- `fix/scope-review` commit `38084016` ("G"): a curated provider-ASN list.
  **Shelved on purpose** (static lists, section 5).

---

## 4. How work is delivered

The operator applies everything themselves. **You never push.** The
workflow, which has been used for every change since 1.0:

1. **Investigate** with commands the operator runs (section 8), and read
   the actual source of any dependency involved.
2. **Propose** the fix in plain terms with the evidence, and wait for a
   go-ahead unless the operator already asked you to build. Questions such
   as "small patch now or fold into the next phase?" are theirs to answer.
3. **Build** on a branch from the current `origin/hypermass-1.1` head:
   - write tests that **reproduce the bug on the old code** (check by
     stashing the fix and watching the test fail), then pass with the fix;
   - run `go build ./engine/... ./config/...`, `go vet` on changed
     packages, `go test ./engine/... ./config/...` and `go test -race` on
     changed packages, and `gofmt -l engine`;
   - review your own diff before committing.
4. **Commit** one commit per change. Author `Claude
   <noreply@anthropic.com>`. End the message with the attribution trailers
   your session specifies (`Co-Authored-By: …` and `Claude-Session: …`).
   **Never put a model name or ID anywhere else** — not in code, comments,
   docs or PR text.
5. **Export** with `git format-patch -1 --stdout > <name>.patch`. Verify it
   applies with `git am` to a clean clone checked out at the base commit,
   and that the resulting tree is identical to your branch.
6. **Deliver**: send the patch file (the operator saves it to
   `~/Downloads`), plus an apply block and a PR link:

   ```bash
   ( set -e
   cd ~/hypermass
   git fetch origin
   git checkout hypermass-1.1
   git pull --ff-only
   test -z "$(git status --porcelain)" || { echo "working tree not clean"; exit 1; }
   test "$(git rev-parse --short=8 HEAD)" = "<base 8-char hash>" || { echo "unexpected base: $(git rev-parse --short=8 HEAD)"; exit 1; }
   git checkout -b <branch>
   git am ~/Downloads/<name>.patch
   git push -u origin <branch>
   )
   ```

   `https://github.com/prisoner881/hypermass/compare/hypermass-1.1...<branch>?expand=1`

7. **After the operator merges**: fetch, confirm the merge commit's tree is
   identical to your commit (`git diff --stat <your commit>
   origin/hypermass-1.1` is empty; the hash differs because `git am`
   rewrites the committer), and confirm `origin/service-detection` is still
   `176be5e5`. Then remind them to rebuild: `sudo docker compose build
   engine enum`, after any running enumeration finishes (a rebuild restarts
   the engine).
8. **Verify on the next run** with a diagnostic block (section 8).

Build notes: the Alpine package mirror occasionally fails a build;
retrying fixes it. `sudo docker compose build --progress=plain enum` once
cleared a stale `enum` image that lacked a new flag.

---

## 5. Constraints and the operator's preferences

These are standing instructions. Treat them as rules.

**Never**
- push, or commit to `service-detection`;
- delete or "clean up" database data. "Everything in the database is
  valuable. There is no bloat to prune." The development database is a
  polluted test database; do not write fixes for old data in it — a
  production database starts fresh;
- modify, fork, patch or send upstream changes to **asset-db** (and treat
  other upstream modules the same unless told otherwise). Work around them
  in Hypermass;
- echo credentials (the database password in `config.yaml` /
  `enum-companies.py`, API keys in `datasources.yaml`) into commands,
  files, commits or messages;
- run anything against the engine or database that writes. Diagnostics
  are read-only.

**Design preferences**
- **No static lists of companies or providers.** "Static lists don't hold
  up over time." Use signals derived from the data (registration,
  ownership evidence, fan-in counts). Vocabularies of words (role words,
  legal-form suffixes, freemail domains, care-of patterns) are acceptable
  because they describe language, not companies.
- **Deterministic and data-driven.** Explain every rule with the record
  that justifies it.
- **Admitting wrong assets is worse than missing right ones**, but missed
  expansion is still a cost; do not trade thoroughness away casually.
  Owned-block fills stay full ("keep full fills unless there's a good
  reason not to").
- **No root-domain flag.** All seeds are equally authoritative; the seed
  fingerprint is built from every seed (section 6.4).
- Fingerprints and veto state are **built fresh each run**, never stored:
  acquisitions converge with their parents over time, and fresh data
  reflects that.
- Re-checking candidates declined earlier in a run was proposed and **not
  wanted**; a later run picks them up.

**Working style**
- Give the operator **commands, not scripts** for diagnostics, and
  explain what each result would mean before they run it.
- **Database queries must be efficient.** The database is large and
  shared with running enumerations; an unindexed query has run past ten
  minutes and been killed. Indexed equality lookups only, with
  `SET statement_timeout = '60s'` (section 8.3).
- The operator runs SQL in **pgAdmin 4 on a Windows workstation**, not
  `psql` on the host: `\o` and host paths do not work; results are saved
  with the Query Tool's "Save results to file"; set
  `SET client_encoding = 'UTF8'` if a WIN1252 encoding error appears.
- Lead with the finding, then the evidence, then the proposal. Correct
  your own earlier mistakes plainly when the data shows them.

---

## 6. The scope design: decisions and the remaining plan

### 6.1 What already shipped (mapped to the names used in discussion)

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

### 6.2 Phase 1 settings chosen by the operator

- `scope_vetoes` default **`enforce`** (the operator chose enforce over
  observe for Phase 1). Ask again before each new phase whether it ships
  enforcing or observing.
- Provenance (`via`, `from`, `distance`) is logged but **not enforced**.

### 6.3 The decision points

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

### 6.4 The seed fingerprint (Phase 3's foundation) — agreed design

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

### 6.5 Remaining phases

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
- Seed fingerprint (6.4).
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

---

## 7. Incident history (what each target taught)

| Target | What happened | Fix |
|---|---|---|
| vistra.com | Cloudflare-fronted domain grew to ~500 CDN/cloud netblocks via ASN fan-out | shared-ASN backstop (13.4.2) |
| crayon.co | WHOIS-proxy address (19,000+ records) pulled in hundreds of registrants; org dedup merged two "On behalf of" orgs | privacy detection, shared-address cap (A, B) |
| blue.cl | Grew into Salesforce Marketing Cloud (17 domains, 2 /16s, 18k IPs) via hosted blocks, address variants, "domain adminstrator" | C, D, E; later N2 |
| Fiserv | First Data Asia-Pacific blocks never attributed; RDAP records silently refused by asset-db | registration range storage (13.5) |
| Mailchimp | ~47,600 IP-THC names dropped by a shared 30 s deadline; Mailchimp's own networks named "MailChimp" with intuit.com contacts read as foreign | per-name deadlines (13.6); seed name match on hold |
| Blackbaud | Batches killed by callers' timeouts in asset-db's single writer; 896 BGP.Tools `<nil>` errors; 17,897 reverse-DNS failures in broken zones | write guard, unrouted networks, reverse caps (13.6–13.8) |
| University at Buffalo | 6,931 forward failures in internal AD/wireless zones; a /16 fill saturated the writer | forward-zone cap, fill pacing (13.8, 13.9) |
| Truist | Repeat target: Known-FQDN replays every stored name at start, IPAddress backlog ~11.6k in minutes | expected; fills wait (13.9) |
| WorldPay | Ran between UB and Truist; not analysed | — |

---

## 8. Diagnostics: how to look at a run

### 8.1 Logs

On the host, `~/amass-docker-compose/logs/amass/`:
- `engine/<date>-amass-engine.log` — one file per UTC day, every session.
- `enum/<date>-enum-<id>.log` — one per run.

Rules learned the hard way:
- **Filter by session ID**, not by time window. `find -mmin -N` selects
  whole files, and the engine file holds every session of the day. Get the
  session ID from the dashboard's first line or the enum log.
- Lines from a **session logger** carry `session=<uuid>`; lines from a
  **plugin logger** (`IP-THC CSV …`, `lookup failed; not marked…`,
  `Plugin started`, `dropped out-of-scope names`) do **not**: filter those
  by timestamp (`awk -v s="$SINCE" '$1 >= s'`).
- Fields inside `[...]` are printed **alphabetically** (`asn=` before
  `asset=`; `asset=` opens the bracket as `[asset=…`). Write `grep -o`
  patterns accordingly, or pick fields by name with `awk`.
- Values with spaces are quoted (`reason="resolution only: …"`).
- Use `LC_ALL=C sort` before `comm`/`uniq`.
- Timestamps are UTC; the operator's dashboard clock is local (US Eastern).

A reusable starting block (fill in the session ID):

```bash
cd ~/amass-docker-compose
L=$(find logs/amass -name '*.log' -mmin -900)
S=session=<session id>
M() { grep -h -F "$S" $L; }
M | head -1 | cut -c1-19; M | tail -1 | cut -c1-19      # run span
M | grep -E '\[(WARN|ERROR)\]' | sed -E 's/^[^ ]+ [^ ]+ (\[[A-Z]+\] [^[]*) \[.*/\1/' \
  | cut -c1-110 | LC_ALL=C sort | uniq -c | sort -rn | head -12   # errors by message
M | grep 'scope decision' | grep -o 'reason="[^"]*"' | LC_ALL=C sort | uniq -c | sort -rn
M | grep 'netblock attributed to seed via RDAP contact' | grep -oE 'cidr=[^ ]*|email=[^ ]*' | paste - - | LC_ALL=C sort -u
M | grep 'asset added to the session scope by horizontals' | grep -oE 'type=[^ ]*' | LC_ALL=C sort | uniq -c
```

Lines worth knowing (all once per session unless noted):
`scope decision`, `netblock attributed to seed via RDAP contact`,
`asset added to the session scope by horizontals` (with `via`, `from`,
`distance`), `skipping location: …`, `skipping organization: …`,
`RDAP registration record not stored`, `failed to store names`,
`no BGP route covers the network`, `reverse DNS zone is not answering`,
`DNS zone is not answering`, `owned-netblock fill paused`,
`owned-netblock fill finished` (with `created`, `paused`),
`failed the maximum number of DNS attempts` (per lookup).

Dashboard: `waiting` = backlog queued, `leased` = claimed and not yet
acknowledged (mostly sitting in pipeline stages), `queue` = pipeline queue.
`NetSem` and `ScanSem` are separate budgets (MAINTAINERS 3.5).

### 8.2 Engine resources

`sudo docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'`.
For an overnight trend, a backgrounded `sudo sh -c '… &'` loop failed once
(the password prompt); have the operator run `sudo -v` first or use a
`tmux` window. pprof is on `127.0.0.1:6060` inside the engine container
(MAINTAINERS 9.2).

The engine API is not published on the host (port 4000 is internal); reach
it at the engine container's IP, e.g.
`GET /api/v1/sessions/<token>/scope/<type>` for a live session's scope.

### 8.3 SQL (pgAdmin, read-only, efficient)

- Start every script with `SET statement_timeout = '60s';`.
- Use indexed equality only. Useful indexes: `ipnetrecord.handle` and
  `record_cidr` (UNIQUE), `netblock.netblock_cidr` (UNIQUE),
  `entity (table_name, row_id)` (UNIQUE), `edge (from_entity_id)`,
  `edge (to_entity_id)`, `entity_tag (entity_id)`,
  `ipnetrecord.start_address`, `organization.org_name`.
- **Never** test ranges (`record_cidr >>= block`) or `LIKE` on big
  tables. To find records covering a block, enumerate the supernets:
  `SELECT set_masklen(b, n) FROM generate_series(8, 24) n` and join on
  `record_cidr = super`.
- Use `MATERIALIZED` CTEs and `LATERAL` subqueries to force small, indexed
  steps; split a big question into two queries.
- `entity.table_name` values look like `'public.netblock'`.
- An `ipnetrecord` row is keyed by RDAP **handle**; since 1.1 it is stored
  under the registered range's CIDR (MAINTAINERS 13.5), so a /24's record
  may sit under a /22. Find it through the netblock's `registration` edge.
- `last_monitored` tags (`entity_tag.property_name = 'last_monitored'`,
  value = source name) show what ran and when (MAINTAINERS 11.4).
- Schema facts: `organization(org_name, legal_name, unique_id)`,
  `identifier(id_value, id_type)`,
  `location(building_number, street_name, city, province, country, unit)`,
  `autnumrecord(asn, record_name, handle)`,
  `ipnetrecord(record_cidr, record_name, handle, start_address, end_address)`.
  Check `\d` (or pgAdmin's column list) before querying an unfamiliar
  table.

Plain example: which RDAP record and contacts sit behind a netblock:

```sql
SET statement_timeout = '60s';
SELECT n.netblock_cidr, r.handle, r.record_cidr, e.updated_at AS linked_at
FROM public.netblock n
JOIN public.entity ne ON ne.table_name = 'public.netblock' AND ne.row_id = n.id
LEFT JOIN public.edge e ON e.from_entity_id = ne.entity_id AND e.label = 'registration'
LEFT JOIN public.entity te ON te.entity_id = e.to_entity_id AND te.table_name = 'public.ipnetrecord'
LEFT JOIN public.ipnetrecord r ON r.id = te.row_id
WHERE n.netblock_cidr IN ('203.17.32.0/24', '203.17.34.0/24');
```

### 8.4 Checking the outside world from the assistant's sandbox

The sandbox has outbound HTTPS only: no DNS resolution, no WHOIS port 43,
no Postgres. Use HTTPS services:
- RDAP: `https://rdap.arin.net/registry/ip/<addr>` (redirects to other
  registries), `/autnum/<asn>`; APNIC `rdap.apnic.net`, RIPE
  `rdap.db.ripe.net`.
- BGP visibility: RIPEstat `https://stat.ripe.net/data/network-info/data.json?resource=<ip>`
  and `/routing-status/data.json?resource=<prefix>`.
- DNS: Google DNS-over-HTTPS `https://dns.google/resolve?name=<n>&type=<t>`
  (status 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN).
- The engine's own RDAP client can be exercised in a throwaway Go test in
  `engine/plugins/api/rdap/` (delete it afterwards).

---

## 9. Building and testing

- Go module `go 1.26.0`. `go build ./...` fails in the sandbox
  (`internal/libpostal` needs the C library); build and test
  `./engine/... ./config/...` instead. The Docker build has libpostal.
- `engine/plugins/load_test.go` starts every plugin against a real
  registry: run it after adding or moving a handler (exclusive positions
  must be unique per event type).
- Tests use SQLite asset databases in `t.TempDir()`. asset-db's SQLite and
  PostgreSQL backends share validation (e.g. an IPNetRecord's CIDR must
  contain its start and end), so most storage bugs reproduce on SQLite. The
  batching single writer does **not** exist on SQLite; database
  concurrency fixes are tested with fakes.
- Fake sessions exist per package; reuse them:
  - `support`: `newP1Session` / `p1Session` (`phase1_test.go`, with a
    scope fake and a captured log), `fillSession`, `scanSession`;
  - `api/rdap`: `newRDAPTest` with `fakeRegistry` (a fake RDAP server and
    IANA bootstrap for 192.0.0.0/22);
  - `horizontals`: `ownerTestSession` + `setScope`;
  - `api`: `newMarkTestEvent` (fake HTTP transport);
  - `dns`: `newReverseTest`;
  - `whois/bgptools`: a fake WHOIS server on localhost;
  - `sessions`: `fakeRepo` for the write guard.
- Pitfalls: `192.0.2.0/24` and other documentation ranges are **reserved**,
  so handlers that skip reserved addresses return early and a test can pass
  for the wrong reason (use a public address such as `74.123.153.77`);
  `FindEntitiesByContent` returns an **error**, not an empty slice, when
  nothing matches; several handlers need transformation TTLs in the test
  config to proceed past their first check.

---

## 10. Things that are easy to get wrong

- **Verify against real source** (asset-db, open-asset-model, the resolve
  library, openrdap) before relying on behaviour. Every wrong assumption in
  this project's history came from reasoning instead of reading or
  measuring (MAINTAINERS 11.2).
- asset-db's PostgreSQL writer is **one connection** batching all writes
  with savepoints under each caller's context (MAINTAINERS 13.6).
- `CreateEdge` silently rejects labels `open-asset-model/relation.go` does
  not allow.
- A **decision made after an asset passed its consumer has no effect**
  unless something re-examines it (owned fills, session-end sweeps).
- Scope can only **grow**. There is no removal except the domain
  blacklist.
- The `scope` package cannot import `support`; it exposes hooks
  (`SkipAssociationEvidence`) that support sets in `init()`.
- Organizations are matched **by name**, and many entities share a name;
  key anything per-organization by normalized name.
- Process-wide caches must be keyed by **database identity + entity ID**
  (`entityCacheKey`), and per-session state must be cleared in
  `support.ForgetSession`.
- RDAP answers can be larger than, smaller than, or not aligned to the
  queried prefix; registries differ (APNIC/RIPE return ranges like
  `203.17.32.0 - 203.17.35.255` as the handle).
- A log line that can repeat per address (fills dispatch whole /24s) must
  be made once-per-session or once-per-network.
- Commands given to the operator must work on their host as typed: test
  regexes against the real log format, avoid `head` truncating the part
  that matters, and say what an empty result means.

---

## 11. Open work, roughly by priority

1. **Phase 2** (N3 vendors/SPF, N4 reverse-DNS operators, sweep vetoes)
   — next agreed phase.
2. **Phase 3** (seed fingerprint, distance limits, N5, N7, NS/MX
   expansion, revised F, seed name match).
3. **Phase 4** (N6 generalized, circuit breaker).
4. Smaller known issues (MAINTAINERS 13.10): RDAP records with one event
   date not stored; the RDAP log line's `from=` shows the record CIDR;
   domain WHOIS on non-registered hostnames; `unspecified IP addresses`
   and empty location city/country errors; only IP-THC retries after store
   failures; the temporary provenance Info line (6.3); decoy detection
   logging (MAINTAINERS 10.3).
5. Unmerged local branches (section 3): ask before reviving.
6. Release 1.1: tag `hypermass-v1.1.0` and write notes from MAINTAINERS
   Part 13 when the operator decides.

---

## 12. Operator tooling outside the repository

Both live in `~/amass-docker-compose` on the host, not in Git.

- **`enum-companies.py`** — runs enumerations one company at a time from
  the database's `companies` and `domains` tables. Pick order: never
  enumerated first (by `run_schedule`: DAILY, WEEKLY, …), then oldest
  `last_enum`; `NEVER`/NULL schedules run only when named on the command
  line (`sudo python3 ./enum-companies.py 28656,411`). Passes the
  company's root domain (`domains.is_root`) first, then the rest
  alphabetically, to `oam_enum -active -silent -scope-json`. Captures the
  `HYPERMASS_SCOPE` line to `./report/scope/<id>.json`. Writes
  `./report/<id>-<name>.xlsx` with tabs Assets, IP's, TP Links, Unknown
  Domains, Tech-Stack, Scope Domains/Netblocks/ASNs/IPs; each tab comes
  from a function in `docs/hypermass_functions.sql` (`fqdn_by_domains`,
  `ips_by_domains`, `tplinks_by_domain`, `other_domains_by_inscope_domains`,
  `techstack_by_domains`), which must exist in the database. Stops the
  queue on any non-zero exit from `oam_enum`. Ctrl-C writes a partial
  report.
- **`report-enumerated.py`** — rewrites reports for every enumerated
  company (up to 5 at once, 15-minute limit each), reusing
  `enum-companies.py`'s report code.
- **`dashboard.py`** — the live terminal dashboard (backlog buckets,
  NetSem/ScanSem, prefilter counts) from the engine API.

`is_root` exists only for ordering the domain list; it carries **no**
special scope meaning (section 5).
