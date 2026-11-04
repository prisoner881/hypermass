# Hypermass — Development Briefing

A hand-off document for an AI assistant (or a developer) continuing work on
Hypermass. It records what the code does not: how the work is done, the
environment it runs in, the decisions already made, the agreed plan, and
what was learned the hard way. Read it together with `docs/MAINTAINERS.md`,
which documents the code itself (Parts 1–12 up to release 1.0, Part 13 for
`hypermass-1.1`).

Sections 1–12 cover the working context. **Section 13** is the changelog:
every change from stock Amass v5.1.1 to now, with what changed and why.
**Section 14** is the feature catalog: every feature the fork adds or
changes, how it works, why it helps, and the details and limits that
matter (14.40 lists where MAINTAINERS disagrees with the code, and
suspected defects not yet fixed).

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
5. Suspected defects found while writing the feature catalog (§14.40):
   HTTP-Probes' dead banner pre-peek, a proxy outage pruning stored
   ports, unbounded SOCKS5 CONNECT waits, process-lifetime dedups (owned
   fill, IP-THC), `ForgetSession` only on end-work, enum hanging if the
   engine dies during end-work, RDAP re-querying empty answers. None is
   confirmed on a run; ask before fixing.
6. Unmerged local branches (section 3): ask before reviving.
7. Release 1.1: tag `hypermass-v1.1.0` and write notes from MAINTAINERS
   Part 13 and §13.4 when the operator decides.

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

---

## 13. Changelog: every change since stock Amass v5.1.1

### 13.1 Sources and conventions

- **There is no CHANGELOG file.** This section is built from the Git
  history of `hypermass-1.1` against the upstream base, plus the PR merge
  commits (#1–#29). Read it together with section 14, which describes
  each feature as it works today.
- **Upstream base:** `79299dce` ("updated to v5.1.1", 2026-04-06), the
  last upstream commit in the fork. Everything before it is stock OWASP
  Amass v5.1.1; everything after it is the fork. `git diff 79299dce
  origin/hypermass-1.1` is the whole fork: 195 files, about 36,000 lines
  added (roughly half of them tests).
- **Three eras:**
  1. **2026-08-21 → 09-21: web uploads.** The operator built the first
     version through GitHub's web upload. About 190 commits say only "Add
     files via upload" or "Update <file>". Their entries below are
     reconstructed from the files each upload touched, the code, and
     MAINTAINERS; dates are commit dates. Tag `sd-freeze-2026-09-10`
     marks the last known-good state of that era.
  2. **2026-09-24 → 10-14: named commits and PRs #1–#10** on
     `service-detection`. Release **1.0** (`hypermass-v1.0.0` =
     `5041be70`). `176be5e5` (MAINTAINERS upload) froze the branch.
  3. **2026-10-15 → 11-03: `hypermass-1.1`, PRs #11–#29.**
- "MAINTAINERS n.n" points to the section of `docs/MAINTAINERS.md` with
  the long story. "§14.n" points to this document's feature catalog.

### 13.2 Era 1 — web uploads (2026-08-21 → 09-21)

| Date | Area / files | What changed | Why |
|---|---|---|---|
| 08-21 | `api/certspotter.go`, `api/dnsdumpster.go`, `api/subdomaincenter.go`, `api/commoncrawl.go`, `api/urlscan.go`, `load.go` | Five subdomain sources added and registered (CertSpotter, DNSDumpster, SubdomainCenter, CommonCrawl, URLScan). | v5 had lost sources that v4 had (SubdomainCenter, CommonCrawl) or never had them; more passive coverage per apex (§14.13). |
| 08-21 | `pagelinks.go` | Page-Links plugin: hostnames from fetched page bodies, with URL→File→URL provenance. | Find names linked from the target's own pages, and record which page they came from (§14.10). |
| 08-21 | `support/fingerprinting.go`, `http_probes/plugin.go` | Error logging added and removed the same day; no net change. | — |
| 08-22 | `enrich/techstack.go`, `go.mod` | Tech-Stack plugin (Wappalyzer over fetched pages) and the `wappalyzergo` dependency. | Identify products and versions on web services (§14.7). |
| 08-23 | `api/server/server.go`, `v1/handlers.go` (`843d61b7`) | `GET /sessions/{token}/backlog` and `GET /handler-stats`. | A live dashboard of backlog, connections and handler cost (§14.33). |
| 08-23 | `api/urlscan.go` (`d6f0e90e`) | URLScan's ASN handler removed; PTR hostnames validated before storage. | The ASN search returned 58,000+ unrelated names on cloud-hosted targets. |
| 08-23–24 | `whois/fqdn_lookup.go`, `whois/rdap.go`, `whois/domain_record.go`, `whois/plugin.go` | Domain lookups try RDAP first, then port-43 WHOIS. | Many registries have stopped answering port-43 WHOIS (§14.16). |
| 08-24–28 | `service_discovery/protocol_probes/*`, `go.mod` (recog-go) | Protocol-Probes: banner peek, classification, Recog matching, TLS certificate harvest, Product storage. Many iterations. | Identify non-HTTP services (SSH, mail, FTP, TLS-only ports) (§14.5). |
| 08-25 | `http_probes/ipaddr_endpoint.go`, `plugin.go` | IP-endpoint probing reworked (banner pre-peek, instance count). | Prepare HTTP probing to read pre-filter results. |
| 08-26 | `ip_netblock.go`, `whois/bgptools/netblock.go` | **New behaviour:** discovered netblocks added to the session scope (first unconditionally, then gated on `HasInScopeFQDN`). Stock never did this. | `Scope.Netblocks()` was otherwise always empty for discovered blocks. This path later caused the CDN leaks (see 09-21, PR #9, PR #21). |
| 08-26 | `dns/ip.go`, `dns/reverse.go` | Provenance authorization (the exact IP an in-scope name resolves to is added to scope); sweep sizing tied to FQDN scope only; DNS-Reverse's PTR sweep removed. | Scan the target's hosts on shared infrastructure without admitting the whole provider block (§14.28). |
| 08-26 | `sessions/session.go` | Session semaphore deadlock fixed (lock not held across a blocking acquire). | A full semaphore froze every plugin (MAINTAINERS 7.1). |
| 08-26–27 | `support/database.go` | `ResolvingFQDNs` / `HasInScopeFQDN` helpers (hydrating edge targets by ID). | The first version returned nothing because edges carry only IDs. |
| 08-30 | `port_prefilter/plugin.go`, `support/portscan.go`, `http_probes/*` | Port pre-filter: TCP connect scan stored as `open_port` tags; HTTP-Probes read them. | Stop probing every configured port on every IP; ~99.9% of probes skipped, a 48 h run became 6 h (§14.2). |
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
| 09-06 | `support/owned_netblock.go`, `support/endwork_progress.go`, `api/rdap/ipnet.go`, `ip_netblock.go`, `bgptools/netblock.go` | Owned-netblock attribution (RDAP contact email on a seed domain → scope at any size) and the fill (every address synthesised and dispatched). End-work progress reporting. | The 10.7 design: scan target-owned space that no name points at (§14.20). |
| 09-06–07 | `internal/enum/cli.go`, `api/client/v1/client.go`, `v1/handlers.go`, `server.go` | `POST`/`GET /sessions/{id}/end-work`; enum waits for the hook before terminating; log stream read in its own goroutine. | The hook needs the session alive; a busy log stream starved enum's idle timer (§14.34). |
| 09-08, 09-11 | `api/thc.go` | IP-THC plugin (passive DNS from ip.thc.org: subdomains, reverse CNAMEs, owned /24s). | High-volume free source of historical names (§14.13). |
| 09-09, 09-12 | `registry/pipelines.go`, `internal/enum/cli.go` | Completed elements Acked when the dispatcher channel is full; handler panics recovered and Acked; enum exits 2 minutes after the hook is done if WorkItems never go idle. | Stranded leases kept enum waiting forever (MAINTAINERS 7.4). |
| 09-10 | `protocol_probes/sweep_query.go` | Postgres batch query for the sweep's miss list, with a serial fallback. | The per-IP walk over thousands of Done IPs was slow. |
| 09-15 | `support/org/find.go`, `org.go` (`0665f470`) | Org dedup ancestor walks bounded (labelled edges, 10 hops, 256 nodes, 32 same-name orgs, 2 s); global lock held only for the final check and create. | "Fix OOM condition caused by unbounded merge": unbounded walks exhausted memory (§14.26). |
| 09-17 | `load.go` (`86388fa2`, `3c47c91b`) | **Wayback, Bing and DuckDuckGo removed from the plugin list** (their files remain). | Not recorded; the commit has no message. Ask the operator before re-adding. |
| 09-19 | `api/alienvault.go`, `load.go` | AlienVault OTX passive DNS. | Additional passive source, ~5 names per apex (§14.13). |
| 09-20 | `api/crtsh.go` | crt.sh's source name fixed (it said "HackerTarget"). | crt.sh and HackerTarget shared one TTL slot; HackerTarget was effectively dark (MAINTAINERS 7.5). |
| 09-21 | `scrape/dnshistory.go`, `scrape/sitedossier.go` | Page loops stop on a non-2xx status or a page with no names. | A blocked source used 19 rate-limiter tokens per seed for nothing (MAINTAINERS 7.6). |
| 09-21 | `ip_netblock.go`, `bgptools/netblock.go`, `support/database.go`, `support/owned_netblock.go` (`038a978e`, `97c6794b`, `b34d02dc`) | Netblock admission given a /20 size limit. **The size check replaced `HasInScopeFQDN` instead of joining it**, and the helper was deleted. | Meant to stop whole cloud /10–/12s entering scope. The replacement admitted every small block any IP fell in, and stayed latent until PR #9 (10-14). |

### 13.3 Era 2 — named commits and release 1.0 (2026-09-24 → 10-14)

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

### 13.4 Era 3 — `hypermass-1.1` (2026-10-15 → 11-03)

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
operator's reports (§14.39).

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

**Docs (this branch):** MAINTAINERS moved to `docs/` and Part 13 added;
this briefing created.

---

## 14. Feature catalog: everything that differs from stock Amass v5

Each entry gives **what** it is, **how it works**, **why** it helps, and
the **details** that matter when changing it (constants, positions,
logs, limits). Paths are under `engine/plugins/` unless shown. Verified
against `e521102b`. Where this disagrees with MAINTAINERS, this section
is the newer reading of the code; §14.40 lists the disagreements.

### 14.1 The plugin set and the pipeline map

**Added** to `load.go`: AlienVault, CertSpotter, CommonCrawl, DNSDumpster,
IP-THC, SubdomainCenter, URLScan (stock had it commented out), Tech-Stack,
Port-Prefilter, Protocol-Probes, Page-Links.
**Removed:** PassiveTotal (commented out, PR #10); **Wayback, Bing and
DuckDuckGo** (deleted from the list in `86388fa2`, no recorded reason;
their source files remain). Hunter.io was already off in stock.

Handlers that share a position form a `Parallel` stage, which handles one
event at a time (MAINTAINERS 10.1). Fork-relevant positions:

| Pipeline | Pos | Handlers |
|---|---|---|
| FQDN | 2, 3, 7, 8, 9 | DNS-CNAME, DNS-IP, DNS-Subdomains, DNS-Apex, DNS-TXT |
| FQDN | 10 / 11 | Horizontals / Known-FQDN (sets `HasSLDInScope` on exact scope domains) |
| FQDN | 14 | WHOIS-FQDN (domain RDAP, then port 43) |
| FQDN | (gate) | OSINT bypass gate, before the first position ≥ 20 |
| FQDN | 22 | AlienVault, CertSpotter, crt.sh |
| FQDN | 23 | DNSRepo |
| FQDN | 25 | SubdomainCenter, HackerTarget, DNSDumpster, URLScan, CommonCrawl, IP-THC-FQDN |
| FQDN | 29 | Prospeo |
| FQDN | 34, 36, 37 | DNSHistory, RapidDNS, SiteDossier |
| FQDN | 41 | HTTP-Probes FQDN (triggers port scans) |
| IPAddress | 2 | BGP.Tools |
| IPAddress | 4 | IP-Netblock |
| IPAddress | 5 | RDAP-IPAddress (per-IP RDAP) |
| IPAddress | 8 / 10 | DNS-Reverse / Horizontals-IP |
| IPAddress | 22 | IP-THC-IP |
| IPAddress | 41 / 42 / 43 | Port-Prefilter (32 inst.) / HTTP-Probes IP (32) / Protocol-Probes (16) |
| Service | 10 / 42 / 43 / 44 | Service-Banner-URLs (stock) / JARM / Page-Links / Tech-Stack |
| Netblock | 2 / 40 | BGP.Tools AS / RDAP-Netblock |
| IPNetRecord, AutnumRecord, DomainRecord | 2 | RDAP-IPNetwork, RDAP-Autnum, WHOIS-Domain-Record |
| Organization, Identifier | 48 | GLEIF |

Exclusive handlers need a unique position per asset type;
`load_test.go` (`TestPluginHandlersRegisterWithoutConflicts`) starts
every plugin and fails on a clash. A stock defect remains: if one
plugin's `Start` fails, `LoadAndStartPlugins` never recorded the started
ones, so nothing is stopped.

### 14.2 Port pre-filter (`support/portscan.go`, `service_discovery/port_prefilter/`)

**What.** A TCP connect scan of `scope.ports` ahead of the expensive
probes. Results are entity tags; HTTP-Probes and Protocol-Probes probe
only ports found open.

**How.**
- Handler `Port-Prefilter-Handler`: IPAddress pos 41, exclusive, 32
  instances, `Transforms: [Service]` (so `IPAddress->ALL` enables it and
  excluding Service disables it with the probes). Requires `-active`;
  gets its dialer from `support.ActiveDialer` (§14.11) and logs
  `skipping port prefilter: no active egress` if there is none.
- `EnsureOpenPortsScanned(e, ent, dial)` is the one entry point (the FQDN
  path uses it too). It returns nothing for: out-of-scope IPs, an empty
  port list, non-routable addresses (§14.12), and **unrouted** /24s
  (§14.28; not marked, so a later session retries). Concurrent calls for
  one IP collapse through a `singleflight.Group`.
- Freshness: `PrefilterTTLStartTime` = the **IPAddress→IPAddress** TTL.
  Within it, cached ports are read; otherwise `scanPorts` runs.
- `scanPorts`: up to `maxConcurrentPortsPerIP = 100` ports at once;
  each dial takes a `ScanSem` slot (cap `MaxScanConns = 3200`, not shared
  with NetSem's 500); a connect = open; no bytes are read. A nil dialer
  scans nothing (fail closed). Direct dial timeout
  `PortPrefilterScanTimeout = 2 s`.
- Storage: `open_port = "<n>"` per open port and `open_port_count` as
  SimpleProperty tags; then `PruneStalePortData` deletes `open_port`
  values not seen in this scan (by value, only if the context was not
  cancelled); then `last_monitored = Port-Prefilter`, even when nothing
  was open. Reads use `OpenPortsForIP(…, since)`, filtering on
  `updated_at`.
- `OpenPortsForFQDN` (FQDN path) resolves up to 5 CNAME hops and scans
  each in-scope IP sequentially; it returns the union of ports.
- Counters `prefilter_scanned` / `prefilter_open` (process-global) feed
  the backlog API.

**Why.** Stock probed every configured port on every in-scope IP. On a
large university ~99.9% of probes were skipped and a 48 h run took 6 h.
Pruning fixes the one false-positive direction: tags upsert by value, so
a port open once would otherwise be reported open forever.

**Details and traps.**
- The 100-port concurrency needs the container's `nofile` at 8,192
  (`compose.yaml`); at Docker's 1,024 default every plugin's sockets fail
  silently (MAINTAINERS 3.4).
- The shipped `resources/config.yaml` lists the stock 6 ports; the
  operator's config uses the nmap top 100.
- If no transformation matches IPAddress→IPAddress, `TTLStartTime`
  errors and **all** IP probing goes silent with no log line.
- `open_port_count` is written but nothing reads it.
- A proxy that dies mid-run makes every dial fail without cancelling the
  context, so the scan "completes" with zero ports, **prunes the IP's
  stored ports**, and marks it scanned for the TTL (inferred from code).
- Port-Prefilter and the FQDN path share one source, so whichever reaches
  an IP first satisfies the other's TTL.

### 14.3 Port ordering and decoys (`support/portpriority.go`, `portfreq_data.go`)

**What/how.** `portfreq_data.go` is a generated map of 8,380 nmap-services
TCP frequencies. Consumers (HTTP-Probes, Protocol-Probes) sort the open
ports with `SortByFrequencyDesc` (unstable for ties). `IsLikelyDecoy(n)`
is `n > LikelyDecoyThreshold (50)`; a flagged IP gets
`DecoyTimeBudget = 90 s` (`DecoyTimeoutChannel` / `DecoyDeadline`,
nil-channel idiom so others stay unbounded).
**Why.** Probe likely services first; bound time on WAFs that SYN-ACK
every port. **Limits:** nothing logs a decoy; with the shipped 6-port
list it can never trip; in HTTP-Probes the budget stops waiting, but the
requests already started still go out.

### 14.4 HTTP-Probes changes (`service_discovery/http_probes/`)

**Stock:** probed every configured port, always marked the asset done,
used the Probe client directly, wrote `Protocol: "TCP"`, 16 IP instances.
**Fork:**
- Ports come from the pre-filter. The IP handler (pos 42, now **32**
  instances) reads them passively; the FQDN handler (pos 41) triggers
  scans through `OpenPortsForFQDN` and builds URLs from the name (SNI).
  Scheme rule unchanged: http on 80/8080, otherwise https.
- Client from `support.ActiveHTTPClient` (`skipping HTTP probe: no active
  egress`); NetSem held around each request; 15 s per request.
- Marks done only when something was probed; an empty port list leaves
  the asset eligible.
- Ports sorted by frequency; decoy budget applied.
- Edge `PortRelation{Name: "tcp_port_<n>", Protocol: "tcp"}` (lowercase;
  consumers compare case-insensitively because old rows say `TCP`).
**Why:** only probe what is open; never send active traffic outside the
proxy; do not record a lookup that never happened.
**Traps:**
- The IP handler's banner pre-peek (skip HTTP on SSH/banner ports)
  passes a **nil dialer**, which since PR #11 fails closed, so the peek
  never sees a banner and every open port gets an HTTP request. It sends
  nothing, so it is not a leak; it is dead code.
- An FQDN whose IPs are all out of scope is not probed (stock probed every
  in-scope name). Names on third-party hosting are probed only because
  DNS-IP's provenance authorization adds their exact IPs (§14.28).

### 14.5 Protocol-Probes (`service_discovery/protocol_probes/`)

**What.** Non-HTTP service identification on open ports. Plugin
`Protocol-Probes` (source confidence 80), handler IPAddress pos 43, 16
instances, transforms Service, TLSCertificate, Product, ProductRelease.

**How (per IP, `-active`, routable, in scope, with fresh open ports).**
1. Dialer from `ActiveDialer` (`skipping protocol probes: no active
   egress`). Ports sorted; decoy deadline set; ports probed one by one.
2. `PeekBanner`: connect, one read of up to 4,096 bytes within
   `PeekTimeout = 2 s`.
3. `ClassifyPeek`: `SSH-` prefix → SSH; other data → ambiguous banner;
   nothing → silent.
4. Banners go to **Recog** (`runZeroInc/recog-go`, fingerprints embedded,
   no external service). The database set is chosen by classification:
   `ssh_banners.xml` for SSH; smtp, ftp, pop, imap, nntp, telnet (in that
   order) otherwise. `BannerCandidates` tries the full banner, then forms
   with the SSH prefix or protocol greeting (`+OK`, `220 `, `* OK`, …)
   stripped, then first and last lines. First match wins.
5. Silent ports get `HarvestCertificate`: TLS handshake (SNI = an
   in-scope name resolving to the IP, if any; `InsecureSkipVerify`). Only
   after a successful handshake is a `tls` Service created and the chain
   stored (`issuing_certificate` edges, `certificate` edge Service→leaf
   carrying the parsed leaf so TLSCert-Expansion links CN/SAN names).
6. Services use `ServiceWithIdentifier(addr, "tcp", port)`, an existing
   Service is reused untouched, the edge is `tcp_port_<n>`, and each
   Service is **dispatched** with a Protocol-Probes source so JARM,
   Page-Links, Banner-URLs and Tech-Stack process it.
7. Recog matches become Product (`Type: software`, vendor in `Category`)
   and ProductRelease, with `product_used` from the Service to both and
   `release` Product→Release; an OS match is a separate Product.
8. The IP is marked done (even if every peek failed).

**Why.** Stock identified only web services. This finds SSH, mail, FTP,
LDAP/IMAP-over-TLS, VPN portals and their versions, and certificate names
on non-HTTP ports.

**Details.** Logs: `Recog fingerprints loaded` at start; `Recog match`,
`Recog no match` (Info, every unmatched banner), `banner peek failed to
connect`, `certificate harvest failed`. A `tls` Service has no Output, so
Tech-Stack and Page-Links skip it. Every silent port gets a TLS attempt.
An IP with no ports yet returns **without marking**, which is what the
session-end sweep (§14.6) catches. Doc comments in `banner_peek.go` and
`certharvest.go` still describe a nil-dialer direct fallback that no
longer exists.

### 14.6 Session-end work: owned fill and Protocol-Probes sweep

**What.** Work that runs once, after the first pass goes idle: finish
owned-netblock fills, re-run Protocol-Probes for IPs whose ports were
found after Protocol-Probes saw them, and drop per-session state.

**How.**
- `NewEngine` sets one hook: `FinishOwnedNetblockFills` →
  `protocol_probes.SweepMissedIPs` → `support.ForgetSession`.
- It runs only via `POST /sessions/{id}/end-work` (`RunEndWork`), once
  per session (later calls return at once). Terminate, Ctrl-C and engine
  shutdown never run it. Both steps are no-ops without `-active`.
- Sweep: wait for the IP pipeline to idle (`sweepIdleTimeout = 2 m`),
  list Done IPs (`Backlog.ListDone`), find misses, resubmit up to
  `sweepMaxResubmit = 500`, wait up to `sweepDrainWait = 15 m`.
- Misses on Postgres: one query per 5,000 Done IDs (90 s context): fresh
  `open_port`, no fresh `last_monitored = Protocol-Probes`, and an
  incoming `dns_record` from a name under a seed or runtime scope domain.
  On error it falls back to a per-IP walk. SQLite always walks.
- Progress: `GET /sessions/{id}/end-work` → `{done, phase, candidates,
  requeued, waiting, leased, processed}`; phases `none`, `owned-fill`,
  `idle-wait`, `listing`, `requeue`, `drain`, `done`.

**Why.** Positions are ordered within one pass, but an IP can reach
Protocol-Probes before its scan finished (another path scanned it later).
Running the hook on stop used to start hours of new scanning.

**Limits.** `ForgetSession` runs only on this path, so a session ended by
terminate keeps its process-wide decision state; the end-work maps are
never freed (small leak); `done` is set even when the hook was cut short;
on Postgres an empty seed list means no sweep at all.

### 14.7 Tech-Stack and product identity (`enrich/techstack.go`, `support/product.go`)

**What/how.** Tech-Stack (confidence 70): Service pos 44, 16 instances,
transform Product. Runs Wappalyzer (`wappalyzergo` v0.3.2) over a
Service's stored headers and body (`FingerprintWithInfo`). For each app:
Product (`Type: software`, categories in `Category`) with simple
properties `icon`, `website`, `cpe`; `product_used` Service→Product;
ProductRelease with `release` Product→Release and `product_used`
Service→Release; a Product event is dispatched. **Angular:** wappalyzergo
never evaluates DOM/JS rules, so `detectAngular` reads
`ng-version="X.Y.Z"` and stores Angular the same way (guarded so a
future library version will not double-store).
**Product identity:** `ProductID = lower(name) + "-" + hash`,
`ProductReleaseName = lower(name) + " " + version`, so Wappalyzer's
"Nginx" and Recog's "nginx" are one entity. Old mixed-case rows are
reused by the source whose spelling matches.
**Why.** Per-service products and versions; one entity per product.
**Details.**
- Product is global (key = name); count `product_used` edges, not
  entities, for identification rates. Versions per host need the
  Service→Release edge.
- Only four edge labels are valid out of a Service (`provider`,
  `certificate`, `terms_of_service`, `product_used`); an invented label
  is rejected silently. Check `open-asset-model/relation.go` first.
- Client-side-rendered frameworks (React, Vue, Next) are rarely
  versioned from static bytes; that is a ceiling, not a bug.
- On an old database where "Nginx-…" exists, Recog's lowercase key can
  still collide on Postgres's case-insensitive natural key (inferred).

### 14.8 JARM (`jarm.go`, `support/fingerprinting.go`)

Service pos 42, 16 instances. Ten TLS handshakes give a 62-character
fingerprint, stored as edge property `JARM` on the port edge. **Fork:**
fingerprint the FQDN/IP, not the Service (stock produced zero
fingerprints ever); `-active` required (stock ran it passively);
case-insensitive protocol; one dialer from `ActiveDialer` for all ten
probes (stock dialled directly); warnings for no targets, failure and an
empty result. It still needs a fresh `certificate` edge, so SSH and
banner Services are skipped silently.

### 14.9 TLS certificate enrichment (`enrich/tls_cert.go`)

Two changes. Certificate contact records are keyed `x509 Certificate:
<serial>, Issuer: <CN>, Subject: <CN>` (was serial only), because default
and self-signed certificates reuse serials and unrelated certificates'
contacts merged. A placeholder subject organization (`IsGenericName`:
"Internet Widgits Pty Ltd", "MyCompany") no longer creates an
Organization. Old serial-only contact records remain in a persistent
database.

### 14.10 Page-Links (`pagelinks.go`)

**What/how.** Service pos 43, 16 instances, transform FQDN, `-active`,
confidence 60. Tokenises the stored page body (`golang.org/x/net/html`)
and reads `href`, `src`, `srcset`, `action`, `formaction`, `data`,
`poster`, `cite`, `longdesc`, `xmlns`. Every hostname is stored (no scope
filter; scope gating keeps out-of-scope names inert). Provenance:
`URL(page) -file-> File -contains-> URL(link) -domain-> FQDN`, plus an
origin anchor `URL(page) -domain-> FQDN` (or `-ip_address-> IPAddress`
when the Service hangs off an IP). Fragments are stripped; at most
`maxLinksPerPage = 1000` URLs per page (hostname extraction is never
capped).
**Why.** Finds names the target links to and answers "which page linked
this host" (`tplinks_by_domain` uses it). **Cost:** ~6 to ~81 URL
entities per page depending on the site. The origin URL uses the last
port edge found.

### 14.11 Active egress (`support/active.go`, `internal/net/active_egress.go`, `config/active_proxy.go`)

**What.** All `-active` traffic through an operator proxy, or not at all.
Operator guide: `docs/active_proxy_egress.md`.

**How.**
- One decision point: `ActiveDialer(sess, timeout)` /
  `ActiveHTTPClient(sess)` → proxy if `active_proxy` is set;
  `ErrNoActiveEgress` ("refusing to send active traffic over the default
  network") if `active_strict` (default **true**); otherwise a direct
  dialer / the Probe client. Callers: Port-Prefilter, the FQDN port scan,
  HTTP-Probes, Protocol-Probes (peek and TLS), JARM.
- Proxies: `socks5://`, `socks5h://` (names sent to the proxy), `http://`,
  `https://` (CONNECT, Basic auth from the URL). Dial timeout 6 s; HTTP
  client timeout 30 s; transport `Proxy` deliberately unset (the dialer
  already proxies).
- Start-up: `CreateSession` refuses `-active` + strict with no proxy, and
  runs `HealthCheck` (one connection through the proxy to `1.1.1.1:443`,
  12 s) when a proxy is configured; a dead proxy refuses the session and
  the reason reaches `oam_enum`.
- Mid-run there is no kill (PR #12): a dead proxy makes active work fail;
  nothing goes direct. SOCKS reply classes: "TTL expired", refused and
  unreachable are target answers; general failure, ruleset refusal and
  unsupported command/address are proxy errors.
- Config `active_proxy`, `active_strict` (YAML options or top-level;
  JSON bodies default `active_strict` to true). CLI `-active-proxy`,
  `-active-strict`. `Config.CheckActiveEgress` validates without side
  effects.
**Why.** Production must send active traffic only from approved egress,
and must fail closed.
**Limits.**
- DNS and passive sources are never proxied (policy). FQDN-based HTTP
  and JARM still let the **proxy** resolve target names.
- With SOCKS5, the 6 s timeout covers reaching the proxy only; the wait
  for the CONNECT reply is bounded by the caller's context, and scans and
  peeks use the session context (no deadline), so a filtered port behind
  Tor can hold a ScanSem slot for minutes (inferred).
- A proxy refusal mid-run looks like a closed port, with no log line.
- The health check runs whenever `active_proxy` is set, even without
  `-active`.

### 14.12 Non-routable filter (`support/nonroutable.go`)

`IsNonRoutableAddress`: invalid, private (RFC 1918/4193), loopback,
link-local, multicast, unspecified, or `amassnet.ReservedCIDRs`. Used by
the pre-filter, Protocol-Probes, DNS-IP (no provenance authorization, no
sweep) and per-IP RDAP. The DNS records are still stored, which reports
internal addresses in public DNS as a finding.

### 14.13 New data sources

All subdomain sources run only on apex names (`HasSLDInScope`, set by
Known-FQDN for exact scope domains), need an FQDN→FQDN transformation,
store through `StoreFQDNsWithSource` (15 s per name, §14.31), and mark
only when the source answered (§14.15) unless noted.

| Source | Endpoint / auth | Pos, confidence | Notes |
|---|---|---|---|
| **AlienVault** | `otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns`, `X-OTX-API-KEY` | 22, 70 | 1 req/s (blocking wait); tries each key, a 401/403 moves to the next; takes `hostname` and `address`; in-scope names only; ~5 names per apex. |
| **CertSpotter** | `api.certspotter.com/v1/issuances?domain=…&include_subdomains=true&match_wildcards=true&expand=dns_names`, optional `Authorization: Bearer` | 22, 100 | Pages with `after=<id>` until empty, no cap; 2 s keyed / one page per 2.4 h unkeyed (process-wide), skips if the wait exceeds 45 s / 10 s; honours `Retry-After` on 429/403; pages fetched before a failure are kept but the apex is not marked. **Needs a key in practice.** No `datasources.yaml` template. |
| **CommonCrawl** | `index.commoncrawl.org/collinfo.json`, then `{cdx-api}?url=*.{apex}&output=json&fl=url&limit=10000` for the 6 newest collections | 25, 60 | 2 s pacing; collection list cached for the engine process; **still marks every lookup**; up to 7 requests per apex. |
| **DNSDumpster** | `api.dnsdumpster.com/domain/{apex}`, `X-API-Key` (required) | 25, 80 | One page (free tier: 50 records); `a`, `cname`, `ns`, `mx` hosts; `error` field is a failure. No template entry. |
| **SubdomainCenter** | `api.subdomain.center/?domain={apex}`, optional `X-API-Key` | 25, 70 | Free tier up to 500 names; `[]` is an answer. No template entry. |
| **URLScan** | `urlscan.io/api/v1/search/?q=domain:{apex}`, `API-Key` (required) | 25, 70 | First page only; own User-Agent (§13.3, PR #8). **Stores every result's `page.domain`/`apexDomain` regardless of scope**, an FQDN→IP `dns_record` edge (TTL 0) per result, and a `ptr_record` edge from `page.ptr`; dispatches them. |
| **IP-THC** | `ip.thc.org/api/v1/subdomains/download?domain=`, `…/cnames/download?target_domain=`, `…/download?ip_address=a.b.c.0/24` (CSV, `limit=50000`, no auth) | FQDN 25 / IP 22, 70 | 2 s pacing; 429/401/403/5xx/transport errors retried, other statuses taken as the answer; in-scope names only; marks only if every name stored. The IP half runs only for IPs in seed-owned netblocks and stores **names only** (THC's rows are passive forward DNS, not PTR). |

**Caveats.**
- URLScan is a horizontal source: its out-of-scope names and IPs enter
  the graph and the pipelines, and its TTL-0 `dns_record` edges present
  historical resolutions as current A records (the thing IP-THC avoids).
  They feed `HasInScopeFQDN` and `ips_by_domains`.
- IP-THC's per-/24 dedup (`rdnsDone`) lives for the engine process: a
  later session in the same engine marks IPs in a /24 already queried
  without querying.
- IP-THC tags: lookups `last_monitored = 'IP-THC'`; stored names
  `SourceProperty` `property_name = 'IP-THC'`, `property_value = '70'`.

### 14.14 Changed upstream data sources

- **crt.sh** — source name `crt.sh` (was "HackerTarget"), confidence
  100; unusable responses are failures.
- **HackerTarget** — "API count exceeded" (plain text, HTTP 200) is a
  failure; other plain text is still an answer (retrying would spend
  quota).
- **DNSRepo** — skips empty credentials; tries each key, then the public
  page; non-200 or undecodable responses move on.
- **RapidDNS** — failures not marked; 200 with no names is an answer.
- **DNSHistory, SiteDossier** — page loops stop at the first non-2xx or
  empty page (1 request, not 19, when blocked). They **still mark every
  lookup and log nothing** when they stop.
- **Prospeo** (FQDN pos 29, transform Identifier, `X-KEY`):
  `GET /account-information` (free) → `POST /search-person` filtered on
  `company.websites` (25 per page, 1 credit per paid page) → `POST
  /bulk-enrich-person` (50 per request, `only_verified_email`, 1 credit
  per email found). Options in `datasources.yaml`:
  `max_emails_per_domain` (default 25; 0 = off) and
  `min_remaining_credits` (default 0). Cost per domain ≤ `ceil(max/25) +
  max`. Masked emails discarded; `NO_RESULTS` is an answer; balance at
  the reserve is a failure (rechecked each session). 1 search/s, 2
  enrich/s. Emails stored as Identifier entities.
- **PassiveTotal** — not loaded.
- **Data-source options** (`config/datasrcs.go`): a data source entry
  may carry `options:` (integers only, `IntOption(name, default)`); a
  non-integer fails the whole YAML parse.

### 14.15 The lookup-outcome rule (`support/lookup.go`)

**Rule.** `MarkAssetMonitored` (`last_monitored = <source>`) only when
the source answered, even with nothing. Transport errors, non-200s, rate
limits, skipped calls and undecodable bodies leave the asset unmarked, so
the next session retries.
**Helpers.** `HTTPLookupFailure(resp, err)` returns the reason or `""`;
`LogLookupFailure` logs `lookup failed; not marked, will retry next
session` with `target`, `reason`, `failures_since_last_log`, at most once
per plugin per minute (to the **engine** log).
**Applied to:** URLScan, HackerTarget, crt.sh, CertSpotter,
SubdomainCenter, DNSDumpster, AlienVault, DNSRepo, RapidDNS, IP-THC,
Prospeo, RDAP, WHOIS, GLEIF. **Not yet:** CommonCrawl, DNSHistory,
SiteDossier, BinaryEdge, Chaos, LeakIX, SecurityTrails, VirusTotal,
ZETAlytics, Grep.App, Aviato.
**Why.** URLScan was dark for two weeks behind a rejected-looking 429
that was recorded as "no results".

### 14.16 Domain WHOIS and RDAP (`whois/`)

**How.**
- WHOIS-FQDN (pos 14, exclusive) runs on registered domains only. It
  tries **domain RDAP first** (`whois/rdap.go`): the IANA bootstrap
  (`data.iana.org/rdap/dns.json`, loaded once per process) gives the
  TLD's server; `GET <base>domain/<name>` at 2 s pacing, honouring
  `Retry-After` on 429. The RDAP JSON is mapped into the same
  `WhoisInfo` shape (registrar, registrant, admin, technical, billing
  from vCards). On any RDAP error, including 404, it falls back to port
  43 (`likexian/whois`, 5 s pacing, 10 s timeout).
- Answered = a record stored, a WHOIS not-found/reserved/premium/blocked/
  other-domain reply, or an RDAP 404 whose WHOIS also found nothing. The
  FQDN is always marked under the WHOIS source.
- `domain_record.go`: placeholder contacts are skipped in **every** role
  (stock: registrant only); a care-of organization or street is not
  stored; a role or placeholder contact name never becomes the
  Organization.
- `privacy_detect.go` (`DetectRegistrantPlaceholder`, threshold 10)
  gains: identity-protection, statutory/organization/name masking,
  pending deletion, confiscated, whoisproxy, domainsbyproxy; "Registrant
  of <domain>" / "On behalf of <domain>" patterns; privacy mail domains
  (and subdomains); hashed mailboxes (32+ hex).
**Why.** Many registries no longer answer port 43; privacy proxies and
placeholders were becoming organizations and addresses.
**Limits.**
- RDAP does not follow the registry's `related` link to the registrar,
  so thin TLDs (.com/.net) may yield fewer contacts than port-43 WHOIS
  did (inferred).
- A failed bootstrap download disables domain RDAP until the engine
  restarts (reported as "no bootstrap entry").
- RDAP-derived contacts are tagged WHOIS; the domain RDAP source is also
  named `RDAP`, like the IP RDAP plugin's.

### 14.17 RDAP for networks and ASNs (`api/rdap/`)

One 2 s limiter (blocking) is shared by all handlers. Source `RDAP`, 100.
`rdapLookupFailure` treats `ObjectDoesNotExist`, `BootstrapNoMatch`,
`BootstrapNotSupported` and `InputError` as answers.

- **Netblock handler (Netblock pos 40).** Within the TTL (30 days in
  production) the record is found through the netblock's own
  `registration` edge; with none it queries again. `store` keeps the
  record under `registeredPrefix(block, start, end)`: the **largest CIDR
  inside the RDAP range that contains the block** (or the block itself
  when the answer lies inside it), so several announced /24s share one
  /22 record, each with its own `registration` edge. The name falls back
  to the handle. A record that cannot be stored logs `RDAP registration
  record not stored` (`cidr`, `handle`, `range`, `reason`) and is not
  marked. After linking, `AdmitOwnedNetblock` checks ownership (once per
  netblock per session).
- **IPNetRecord handler (pos 2).** Stores contacts (stock) and then
  `admitParentNetblock`: checks the record's ownership **once**
  (`IPNetRecordOwnedBySeed`) and only then admits its linked netblocks
  (up to 256).
- **Per-IP handler (IPAddress pos 5, new).** For routable IPs that an
  in-scope name resolves to, not inside an in-scope netblock and not
  covered by an earlier answer this session: query RDAP by address; split
  the answer's range into at most 8 CIDRs; keep those more specific than
  the IP's BGP prefix (or ≥ /16 IPv4, ≥ /32 IPv6 without one); store each
  as a Netblock (marked looked-up) with its record. The normal ownership
  check then decides.
- **Contacts:** no Location for a care-of address; no Organization for a
  role, placeholder or care-of name.
- **ASN handler:** marks only when answered.
**Why.** Ownership comes from registration contacts; the record must be
stored where it belongs and fetched early enough. A BGP aggregate's RDAP
answer is the provider's; a reassignment to the target is visible only by
address.
**Limits.** Answers that store nothing (404, no bootstrap match, a record
missing either date: some AFRINIC/APNIC) are re-queried on every Netblock
event; asset-db upserts records by handle, so a range stored under
different blocks keeps whichever was written last; per-IP RDAP has no
cross-session TTL.

### 14.18 BGP.Tools (`whois/bgptools/`)

Port-43 WHOIS to `bgp.tools`, 1 req/s. **Fork:** socket deadline from the
10 s context (a silent server used to hang the IP pipeline); the mutex is
released around the query and the cache re-checked after (11/min → demand
driven); `<nil>` or empty prefix = `errNoRoute`: the /24 (/48) is
recorded unrouted for the session, logged once (`no BGP route covers the
network; its addresses are not looked up`), and its other addresses are
skipped; netblock admission as in §14.20. Failures store nothing and
recur (no marking).

### 14.19 GLEIF (`api/gleif/`)

One `gleifGet` helper: 3 s global limiter, 60 s timeout; 404 or an empty
search = `ErrGLEIFNotFound` (an answer); other statuses are failures.
Stock returned `(nil, nil)` for a non-200, which the fuzzy handler stored
as a confidence-100 match. The related-organization handler stores what
it got and marks only when both parent and children requests completed.

### 14.20 Netblocks: ambient admission, ownership and the owned fill (`ip_netblock.go`, `whois/bgptools/netblock.go`, `support/owned_netblock.go`)

**Stock** IP-Netblock and BGP.Tools stored the Netblock, AS and their
edges but **never added a netblock to scope**. The fork added that on
08-26 (§13.2), then had to fence it in (PRs #9, #21).

**Ambient path (now vetoed).** When a block is IPv4 /20 or smaller
(`PrefixEligibleForAmbientAdmit`) and an in-scope name resolves to the
IP (`HasInScopeFQDN`), the code calls `Decline(VetoResolutionOnly)`. In
`enforce` it declines, so resolution alone never admits a block. In
`observe` or `off` the 1.0 behaviour returns.

**Ownership path (`AdmitOwnedNetblock`).** Called from BGP.Tools (IP pos
2), IP-Netblock (4), the RDAP netblock handler (Netblock 40) and RDAP's
`admitParentNetblock`.
- A block is owned when one of its RDAP registration's contacts
  (registrant, admin, abuse, technical) has an email on a seed domain or a
  subdomain of one (`NetblockOwnedBySeed`, `seedContactEmail`). Fails
  closed on missing data.
- Owned blocks are added to scope **at any size**, regardless of
  `scope_vetoes` and `-active`, once per session per CIDR. Log `netblock
  attributed to seed via RDAP contact` (`cidr`, `email`, `distance`).
  Distance is one step from the email's seed domain.
- In practice the `registration` edge rarely exists at IP pos 2/4; the
  RDAP handlers (pos 40, IPNetRecord 2) and session end do the real work.

**Owned fill.**
- With `-active`, an owned IPv4 block of /16 or smaller
  (`ownedMinPrefixBits = 16`) is filled: every usable address is created,
  linked with a `contains` edge, and dispatched (resubmitted if already in
  the backlog), so each passes Port-Prefilter itself.
- Starts mid-run when the block is attributed; `FinishOwnedNetblockFills`
  at session end covers blocks attributed late, then waits (up to 3 h)
  for the IPAddress backlog to drain.
- **Pacing:** every 64 addresses, wait while IPAddress queued + leased ≥
  2,048 (`ownedFillMaxBacklog`); log `owned-netblock fill paused…` once.
- Logs: `starting owned-netblock fill`, `owned-netblock fill progress`
  (every 4,096), `owned-netblock fill finished` (`created`, `dispatched`,
  `skipped`, `paused`).
- **Full fills are policy**; do not add a size cap below /16 without
  asking.
- **Limit:** the once-per-CIDR guard (`ownedFillOnce`) lasts for the
  engine process, so a long-lived engine running several sessions never
  re-fills a block filled by an earlier session.

**Helpers.** `IPInOwnedNetblock` (IP's `contains` edges → owned block),
used by IP-THC and PTR attribution. IP-Netblock no longer waits 30 s for
a BGP prefix on unrouted /24s.

### 14.21 Scope vetoes framework (`support/scope_decision.go`, `config/scope_vetoes.go`)

**Setting `scope_vetoes`:** `enforce` (default, also for an empty or
unknown top-level value), `observe` (log `would decline`, keep the old
behaviour), `off`. In the YAML `options:` map an unknown value or a
non-string fails config loading.

**`Decline(sess, reason, type, asset, plugin, kv…)`** logs Info `scope
decision` (`action`, `reason`, `type`, `asset`, evidence, plugin) once per
session, reason and asset, and returns true only in `enforce`. Reasons:

| Constant | Logged reason | Extra fields |
|---|---|---|
| `VetoResolutionOnly` | resolution only: an in-scope name resolving into a netblock does not make it the target's | `asn` |
| `VetoForeignRegistrant` | registration names another organization | `registrant`, `email_domains` |
| `VetoMergedCertificate` | merged certificate: unrelated certificates share this serial number | `common_name` |
| `VetoSharedASN` | shared infrastructure: the ASN announces too many netblocks | `announced_netblocks`, `max_announced_netblocks` |

**Only these four depend on the setting.** Shared-address, role and
placeholder, care-of, "hosting is not ownership", the ≤ /20 ASN fan-out
filter and non-routable exclusion apply in every mode.

**Provenance.** `RecordScopeAddition` keeps each asset's shortest
distance from the seeds (seeds 0; −1 unknown, not stored); organizations
are keyed by normalized name. Horizontals logs `via`, `from`,
`distance` on additions (association logs `via=association` and
`distance`, no `from`). **Recorded, not enforced** (Phase 3).

**State.** Per-session maps are cleared by `ForgetSession` (only on the
end-work path, §14.6). Process-wide verdict caches (shared addresses,
merged certificates) are keyed by `entityCacheKey`: database identity +
entity ID, because IDs are unique only per database.

### 14.22 Registration verdict (`support/registration_verdict.go`)

`RegistrationVerdict(ctx, sess, rec)` for an IPNetRecord or AutnumRecord:
- **Owner:** any contact email on a seed domain (or subdomain), or the
  registrant organization in scope (exact name, confidence 100).
- **Foreign:** a real registrant organization (not role, placeholder or
  care-of) that is not in scope **and** a contact email on a domain that
  is neither freemail (~55 listed providers) nor in scope.
- **No information:** everything else (redacted records land here).
Owner beats foreign. `DeclineForeignRegistration` vetoes a foreign
record; callers exempt seeded CIDRs and ASNs. **Known miss:** a
target-run network registered under a parent company's email domain
reads as foreign (Mailchimp: "MailChimp" with intuit.com contacts; the
seed-name-match proposal is on hold).

Also here: per-session RDAP range tracking for per-IP RDAP
(`RDAPRangeKnown`, `RecordRDAPRange`), `RangeToPrefixes`, `LastAddr`,
`RegisteredDomain`.

### 14.23 Evidence filters

| Filter | File | Rule | Effect |
|---|---|---|---|
| Care-of / mail drop | `support/care_of.go` | `c/o`, `care of`, `PMB 255`, `#` + 5 or more digits | WHOIS/RDAP keep the org and email but do not link the address; such an address counts as shared at once; care-of text in an organization field drops the organization. |
| Role names | `support/role_names.go` `IsRoleName` | every word from a role vocabulary, at least one head word (admin, hostmaster, manager, contact, department, noc, owner, billing, technical, abuse, …) | Not an organization. |
| Placeholders | `IsNonName` | whole-value match ("N/A", "None", "Unknown", "Private Person", "Individual", "Internet Widgits Pty Ltd", "Default Company Ltd", "MyCompany", …) or no letters/digits | Not an organization. Whole-value, so "Private Equity Partners LLC" is kept. |
| Shared addresses | `support/shared_location.go` | more than `MaxRecordsPerLocation = 25` records across every stored variant of the building (number, street, city, province) | Horizontals neither admits nor walks it; org dedup does not merge on it; logged once per session. Only shared verdicts are cached (process). |
| Merged certificates | `support/merged_cert.go` | CNs across more than one registered domain, or subject contacts naming more than one real organization | Not used by horizontals or association evidence (`scope.SkipAssociationEvidence` hook). Mode-dependent (`VetoMergedCertificate`). |

`IsGenericName` = role or placeholder; `SkipRoleOrganization` logs
`skipping organization: a role or placeholder name, not an
organization`; `SkipSharedLocation` logs `skipping location: shared
address (likely a privacy proxy, registered agent or host)` or `…:
care-of or mail-drop address`. A location admitted while under the cap
stays in scope after it crosses it (scope never shrinks).

### 14.24 Horizontals (`horizontals/`)

**Every handler:** additions log `asset added to the session scope by
horizontals` with `type`, `asset`, `via`, `from`, `distance` (stock was
silent); role organizations and shared locations are skipped at entry
and filtered out of contact records.

**Registration records (`reg_records.go`):**
- **AutnumRecord:** in scope → expand unless foreign; out of scope →
  needs a registrant match and not foreign, then the ASN fan-out.
- **DomainRecord:** in scope → expand; a match queues the **FQDN** (stock
  queued the record). No foreign veto for domains.
- **IPNetRecord:** counts as in scope if the record is, or (when owned by
  a seed email) any linked netblock is. In scope **and owned** → expand.
  In scope but not owned → expand only on a registrant match, otherwise
  log `not expanding scope from netblock registration: registrant not
  attributed to the target`. A match admits **all** linked netblocks
  (`getRegisteredNetblockEntities`: incoming `registration` edges, cap
  64, any size) unless foreign.

**`expandFromContactRecord`** (Organization and Location walks) applies
the same per-type rules to every record using an in-scope org or address;
certificates go through `enqueueCertificateDomain` (the CN's registered
domain) unless merged.

**ASN fan-out (`addASNetblocksToScope`):** an AS announcing more than
`maxAnnouncedNetblocksForScope = 500` blocks → `VetoSharedASN` (in
enforce not even the AS enters scope); under the cap only IPv4 ≤ /20
blocks are admitted (stock admitted all). 16 was tried first and caught
American Express (119) and Bank of America (98). **No provider list**, by
the operator's policy.

**IP handler:** follows the `.arpa` PTR edge. It **still sweeps** 32
neighbours (64 with `-active`) when the PTR name is in scope; swept IPs
are submitted but not added to scope.

### 14.25 Session scope (`engine/sessions/scope/`)

- `Add(TLSCertificate)` adds the CN's registered domain (eTLD+1,
  wildcard stripped); stock passed the host CN, which added nothing.
- `SkipAssociationEvidence` hook: merged certificates are not used or
  traversed as association evidence.
- Unchanged matching: domains by suffix; IPs by containment or exact;
  netblocks by exact CIDR; organizations by exact case-insensitive name
  (the fuzzy branch never fires at the confidences used); locations by
  building number + street + city + province. Scope only grows.
- Association evidence still has no foreign or distance check (indirect
  protection only, via the filters).

### 14.26 Organization dedup (`support/org/`)

- **OOM fix (`0665f470`):** ancestor walks follow only organization,
  id, subsidiary, registration and contact edges, at most 10 hops, 256
  nodes, 32 same-name organizations, 2 s per walk. An aborted walk means
  "no match", so a new organization is created (more duplicates on dense
  graphs, never an unbounded merge). Logs `org ancestor walk skipped` /
  `aborted`.
- Shared addresses are never merge evidence (crayon.co / kitche.co).
- `CreateOrgAsset` takes the global lock only for the final re-check and
  create (stock held it through the walks).

### 14.27 How an asset gets into scope now

| # | Path | Admits | Checks applied |
|---|---|---|---|
| 1 | Seeds (`scope.domains`, `cidrs`, `asns`, `ips`) | distance 0 | none; seeds exempt their records from the foreign veto |
| 2 | Names under an in-scope domain | by suffix match | — |
| 3 | Association (Horizontals FQDN/Org/Location on an out-of-scope asset) | the submission | `-rigid` blocks; merged-cert hook; role/shared filters; no foreign veto |
| 4 | Registration records (Horizontals pos 10) | the record's domain, AS, or all linked netblocks | foreign veto (not domains); hosting ≠ ownership; shared-ASN cap; `-rigid` blocks |
| 5 | Organization / Location walk | what each linked record registers | same as 4; certificates: merged veto |
| 6 | TLS certificate handler | CN's registered domain and orgs | merged veto; role filter |
| 7 | Ambient netblock (resolution + ≤ /20) | — | `VetoResolutionOnly`: never in `enforce` |
| 8 | Ownership (RDAP contact email on a seed domain) | the netblock, any size; fill with `-active` | not subject to `scope_vetoes` |
| 9 | Provenance IP (DNS-IP) | the one IP an in-scope name resolves to | non-routable excluded; not subject to vetoes or `-rigid`; never triggers a fill |
| — | DNS-IP 25-address sweep, Horizontals-IP PTR sweep | submitted, **not** scoped | — |

### 14.28 DNS (`dns/`, `support/reverse_dns.go`, `support/unrouted.go`)

- **DNS-IP (FQDN pos 3):**
  - **Provenance authorization:** for an in-scope name, each routable
    resolved IP is added to scope as an exact address (Info
    `provenance scan authorization: added IP to scope`, temporary and now
    the busiest line).
  - The neighbour sweep is sized by FQDN scope only (25); stock swept
    100/250 around in-scope IPs. `secondSweepSize` and `maxSweepSize` are
    now unused.
- **DNS-Reverse (IP pos 8):**
  - The PTR-triggered sweep is removed.
  - `attributeOwned`: an in-scope PTR name of an IP in an owned block
    gets `IP -ptr_record-> host` and `apex -node-> host` (skipped when
    the name spells the address; `ptrNameEmbedsAddress`).
  - Outcomes are recorded per /24 (/48); 5 failures (all six attempts
    each) with none answered → `reverse DNS zone is not answering; its
    other addresses are not looked up`.
- **Forward handlers (DNS-IP, CNAME, TXT, Subdomains):**
  - Skip `in-addr.arpa`/`ip6.arpa` names (`IsReverseDNSName`).
  - Skip broken zones: a zone is the name minus its first label, never
    the registered domain; 10 distinct names failing with none answered
    → `DNS zone is not answering; forward lookups of its other names are
    skipped`.
  - NXDOMAIN and "no record of this type" are answers and keep a zone
    open.
- **Unrouted networks:** BGP.Tools' no-route answer marks the /24 (/48)
  for the session; BGP.Tools, IP-Netblock and the pre-filter skip it.
  Filled addresses there still get reverse DNS.
- **Retries:** `PerformQuery` makes at most 6 attempts (was 10).
- **Why:** dead zones on owned fills (Blackbaud, University at Buffalo)
  produced tens of thousands of six-attempt failures. All state is per
  session, so a fixed zone is retried next run.
- **Edge case (inferred):** a reply holding only another record type is
  retried and can count as a failure.

### 14.29 Resolvers (`support/resolvers.go`)

Read once per engine process at start-up:
- `AMASS_ENGINE_RESOLVERS` — comma-separated IPs or a file (one per line,
  `#` comments), replacing the built-in list when at least one is valid;
- `AMASS_ENGINE_RESOLVER_QPS` — aggregate cap for the pool (0/unset = no
  cap);
- `AMASS_ENGINE_WILDCARD_RESOLVER` — default `8.8.4.4`.
Logged as `trusted DNS resolvers: …` (warning if the list held no valid
address; bad QPS or wildcard values are ignored silently). The unmerged
`feat/resolver-per-ns-ceiling` branch would lift the library's per-server
ceiling; ask before reviving it.

### 14.30 FQDN OSINT bypass gate (`engine/registry/osint_bypass.go`)

A FIFO stage before FQDN position 20. Exact configured domains (flagged
with `HasSLDInScope` if missing, which also fixes overlapping configured
domains) and names Known-FQDN flagged take the OSINT path (20–40).
Everything else jumps to the first stage after 40 (HTTP probing).
`assertOSINTBypassInvariant` panics at pipeline build if a handler in
20–40 is not on the 22-name skippable list. **Why:** one slow scope
domain in a one-wide `Parallel` stage held every discovered name behind
it. **Amplifier:** any runtime scope domain gets full subdomain OSINT, so
admission must stay strict.

### 14.31 Database helpers and the write guard

- **`storeEach`** (`support/database.go`): `StoreFQDNsWithSource` and
  `StoreEmailsWithSource` give each item its own 15 s deadline
  (`storeItemTimeout`; stock: one 30 s deadline per batch), stop when the
  session ends, and log one `failed to store names` / `failed to store
  email addresses` line (`failed`, `stored`, first `error`).
  `StoreFQDNsWithSourceCount` returns the failures (only IP-THC uses it to
  stay unmarked).
- **Other helpers:** `ResolvingFQDNs`, `HasInScopeFQDN`,
  `PreferredSNIHostname`, `ResolvedIPsForFQDN`, the port tags (§14.2).
- **Write guard** (`engine/sessions/write_guard.go`): the session wraps
  its repository; all 11 create/delete methods run under
  `context.WithTimeout(context.WithoutCancel(ctx), 5 m)` in a goroutine.
  The caller waits only for its own context; if that ends first it gets
  its error while the write finishes in the background (idempotent
  upserts). A write whose caller already gave up is never submitted.
  Reads pass through.
- **Why:** asset-db's Postgres repository has one writer connection and
  runs a batch of everyone's writes in one transaction under each
  caller's context; one caller's timeout closed the connection and failed
  the batch. asset-db must not be modified.
- **Limits:** background write errors are invisible; a write queued past
  5 minutes still kills its batch; the single writer is the throughput
  ceiling.

### 14.32 Dispatcher, backlog and semaphores

- **Stranded leases** (`registry/pipelines.go`): a completed element
  that cannot be sent to the dispatcher's full channel is Acked directly;
  handler panics are recovered (`panic in <handler>: …`) and Acked.
  `SetLeaseTTL(0)` (never reclaim) is unchanged on purpose. On the
  direct-Ack path the dispatcher's meta entry and the element's error are
  not handled.
- **Backlog:** `ListDone(type)`; `Dispatcher.ResubmitEvent` on the
  interface; `ClaimNext`'s shadowed `ttl` renamed (no behaviour change).
- **Semaphores** (`sessions/session.go`, `internal/net/network.go`):
  `Acquire`/`Release` no longer hold the session lock while blocking
  (stock deadlock). `ScanSem` (`MaxScanConns = 3200`, one per session,
  never resized) for connect scans; NetSem (500 divided by sessions) for
  everything else. `InUse()`/`Cap()` for the dashboard.
- `CreateSession` refuses a nil scope (`the configuration has no scope`)
  and applies the active-egress checks.

### 14.33 Engine API (`engine/api/`)

- **New endpoints:**
  - `GET /api/v1/sessions/{token}/backlog` → `buckets[]` (`asset_type`,
    `waiting`, `leased`, `queue`, `processed`), `active_connections`,
    `max_connections`, `active_scan_conns`, `max_scan_conns`,
    `prefilter_scanned`, `prefilter_open`.
  - `POST /sessions/{token}/end-work` (202) and `GET` (progress, §14.6).
  - `GET /api/v1/handler-stats` (InfluxDB, 15-minute averages; returns
    503 because no InfluxDB is configured, by decision).
- **Fixes (PR #14):**
  - `PutAsset`/`PutAssets` return the database's error instead of
    dereferencing a nil entity; bulk goroutines recover panics and count
    the item failed.
  - An asset with no identifying value → 400; a missing `scope` → 400.
  - Create-session refusals carry the reason in `details`, which the
    client appends to its error.
- **Log stream** (`pubsub/logger.go`, `v1/websocket.go`): one queue and
  one pump goroutine per subscriber (the only sender, which closes the
  channel); `Unsubscribe`; the WebSocket reads the connection, pings
  every 30 s and ends on disconnect or 60 s without pong; session end
  sends a close frame. Stock leaked one goroutine per message after a
  client left. **Limit:** a slow but live client's queue is unbounded.
- **Docs:** `docs/engine_api.md` (full orchestrator reference, checked
  against a running engine) and regenerated Swagger (`docs/docs.go`,
  `swagger.yaml`, swag v1.16.6). The CIDR scope form is Go's
  `net.IPNet` JSON (`{"IP":…, "Mask":"<base64>"}`), not a string.

### 14.34 The `enum` CLI (`internal/enum/`)

- **New flags:**
  - `-active-proxy <url>`;
  - `-active-strict` (default true; overrides config only when given);
  - `-scope-json`.
  - The `-active` help now describes what it does.
  - `-active` + strict with no proxy exits 1 before contacting the
    engine.
- **Session end:**
  - After 5 idle polls (2 s apart), or when the `-timeout` no-progress
    timer fires (default 30 minutes; 0 or less = 24 h), enum POSTs
    end-work ("First pass idle. Starting session-end work...").
  - It then polls `GET /end-work`. It exits when done and idle for 5
    polls, or 2 minutes after done if WorkItems never go idle (Warn
    `session-end hook done but WorkItems not idle`, the stranded-lease
    safety net).
  - It prints `Waiting for session-end hook to finish...` every 30 s.
- **The log stream** is read in its own goroutine (a busy stream used to
  starve the idle ticker).
- **Seed creation** timeout raised to 4 s.
- **`-scope-json`:**
  - Just before termination (also on Ctrl-C and under `-silent`) it
    prints one `HYPERMASS_SCOPE {"session":…,"fqdn":[…],"netblock":[…],
    "autonomoussystem":[…],"ipaddress":[…]}` line.
  - Lists are sorted (CIDRs and IPs numerically).
  - A type that could not be read is listed under `errors`, so a wrapper
    can tell "none" from "unknown".
  - `enum-companies.py` saves it for the report's Scope tabs.
- **Limit:** once end-work starts, enum resets its no-progress timer on
  every tick, so if the engine dies it waits until Ctrl-C.

### 14.35 Configuration summary

| Setting | Where | Default | § |
|---|---|---|---|
| `active_proxy` | config / options / `-active-proxy` / API JSON | none | 14.11 |
| `active_strict` | same / `-active-strict` | true (also for API JSON that omits it) | 14.11 |
| `scope_vetoes` | top-level or options | enforce | 14.21 |
| data source `options` | `datasources.yaml` per entry, integers | — | 14.14 |
| `AMASS_ENGINE_RESOLVERS`, `_RESOLVER_QPS`, `_WILDCARD_RESOLVER` | engine environment | built-in list, no cap, 8.8.4.4 | 14.29 |
| `nofile` 8192 | `compose.yaml` (deployment, not code) | Docker 1024 | 14.2 |

`resources/config.yaml` gained only comments for the first three.

### 14.36 Start-up diagnostics

- `engine build info` (`amass_version`, `vcs_revision`, `vcs_modified`,
  versions of wappalyzergo, resolve, asset-db, open-asset-model) from
  `debug.ReadBuildInfo`. A missing revision means the Docker build
  context had no `.git`.
- `trusted DNS resolvers: …` from the engine CLI.
- `Recog fingerprints loaded`.
- pprof on `127.0.0.1:6060` is stock but essential (MAINTAINERS 9.2).

### 14.37 Dependencies (`go.mod`)

- **New direct:**
  - `projectdiscovery/wappalyzergo v0.3.2` (Tech-Stack);
  - `runZeroInc/recog-go` (Protocol-Probes, fingerprints embedded);
  - `golang.org/x/sync` (singleflight).
- **Bumped:** `x/net` (`x/net/proxy` for SOCKS5), `x/crypto`, `x/sys`,
  `x/text`, `x/tools`, `testify`, `yaml/v3`.
- **Unchanged:** Go 1.26, asset-db v0.24.4 (must stay unmodified),
  open-asset-model, resolve.

### 14.38 Tests that guard the fork

- `engine/plugins/load_test.go` — handler position conflicts.
- `support/active_test.go`, `internal/net/*_test.go` — a local SOCKS5 and
  CONNECT proxy; active traffic reaches the target only through the
  proxy; a dead proxy sends nothing direct.
- `sessions/write_guard_test.go`, `sessions/*_test.go` — the guard;
  CreateSession refusals.
- Per-plugin marking tests against canned HTTP servers and a SQLite
  asset database (each failure case fails on the old code).
- `support/*_test.go` — vetoes, verdicts, care-of, shared addresses,
  merged certificates, distances, unrouted and zone caps, fill pacing.
- `dns/reverse_names_test.go`, `bgptools_test.go` (fake WHOIS server),
  `rdap/registered_range_test.go`, `horizontals/registered_range_test.go`.
- Build/test only `./engine/... ./config/...` in the sandbox (section 9).

### 14.39 Docs and SQL in the repo

- `docs/MAINTAINERS.md` (code reference), this briefing,
  `docs/active_proxy_egress.md` (operator guide), `docs/engine_api.md`
  (orchestrator reference), Swagger.
- `docs/hypermass_functions.sql`, applied in one transaction (fails fast
  if the asset-db schema is missing; `CREATE OR REPLACE`, so drop a
  function first if its result columns change). Input is always one
  comma-separated domain string.
  - **`fqdn_by_domains(domains)`** — every `fqdn` row equal to or under
    the domains (`reverse_fqdn` match). Note: it uses `LIKE`, so `_` in a
    domain is a wildcard.
  - **`ips_by_domains(domains, since, include_neighbors, max_cname_depth)`**
    — one row per IP with `reasons[]` and `evidence[]` from five paths:
    `forward_dns` (CNAME chain then A/AAAA), `ptr`, `cert` (SAN/CN →
    certificate → service → IP), `owned_netblock` (contact email at a
    listed domain → IPNetRecord → Netblock → contains), and optional
    `neighbor`; `since` filters edges by `updated_at`.
  - **`tplinks_by_domain(domains)`** — third-party registered domains
    reached by NS/CNAME/MX/SRV records or page links, with
    `host -> TYPE -> host` evidence, using `public.public_suffix_list`.
    The fqdn type id is hard-coded (7).
  - **`other_domains_by_inscope_domains(domains)`** — those third-party
    domains not in any company's `public.domains` row ("Unknown Domains"
    tab).
  - **`techstack_by_domains(domains)`** — per host, service type, ports,
    product, type, release, icon, website, CPE and the identifying plugin
    (Protocol-Probes or Tech-Stack). It checks its hard-coded type ids at
    start and raises if they differ. VOLATILE (temp tables), so it cannot
    run on a read-only standby.

### 14.40 Where MAINTAINERS (and other docs) disagree with the code

Found while building this catalog. MAINTAINERS has not been corrected
yet; prefer the code.

1. **Part 6:** IP-Netblock and BGP.Tools did **not** add netblocks to
   scope in stock; the fork added that (08-26).
2. **Part 6 / `dns/reverse.go` comment:** the removed PTR sweep did fire
   in stock for seeded CIDRs and addresses. Since its removal (and DNS-IP's
   smaller sweep), only owned fills cover whole blocks.
3. **Part 6:** the Horizontals-IP PTR sweep (32/64) still exists.
4. **4.1:** the IP handler's banner pre-peek is dead since PR #11 (nil
   dialer).
5. **4.2:** Recog databases are chosen by peek classification, not by
   port; SSH patterns match the software field (`OpenSSH_7.4`), with the
   prefix stripped.
6. **6.1:** there is no separate cloud/personal-mailbox check; freemail
   fails only because it is not a seed domain. The fill guard lasts for
   the process, not the session.
7. **7.6:** DNSHistory and SiteDossier stop after one request when
   blocked, but **silently**, and still mark the lookup.
8. **9.2.1 / Part 8:** the hook's third step is `ForgetSession`; `POST
   /end-work` exists; phases include `none` and `owned-fill`. pprof is at
   `engine.go:37`.
9. **10.1:** position 22 also holds AlienVault.
10. **13.1:** the 6 s proxy timeout is end to end only for HTTP CONNECT
    (SOCKS5: see §14.11).
11. **13.4.6:** "enforce for empty/unknown" holds for the top-level field
    only; in `options:` an invalid value fails loading. `off` also
    restores the ambient admission silently. Association additions log no
    `from=`.
12. **Undocumented there:** the Wayback/Bing/DuckDuckGo removal;
    URLScan's out-of-scope storage and TTL-0 `dns_record` edges; IP-THC's
    process-wide /24 dedup; CertSpotter needing a key; CommonCrawl still
    marking every lookup; domain RDAP's limits (§14.16).
13. **`docs/engine_api.md`:** the CLI `-timeout` default is 30 minutes
    (24 h only for 0 or less), and the engine itself reads the three
    `AMASS_ENGINE_*` resolver variables.

**Suspected defects, not fixed** (raise with the operator before
changing):
- HTTP-Probes' dead banner pre-peek (§14.4);
- a proxy outage pruning stored ports (§14.2);
- SOCKS5 CONNECT waits bounded only by the session context (§14.11);
- the owned-fill and IP-THC dedups lasting for the process rather than
  the session (§14.13, §14.20);
- `ForgetSession` only on the end-work path (§14.6);
- enum waiting forever if the engine dies during end-work (§14.34);
- Netblock RDAP re-querying answers that store nothing (§14.17).
