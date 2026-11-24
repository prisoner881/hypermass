#!/usr/bin/env python3
"""Enumerate companies from assetdb one at a time.

After each company finishes, the next pick is read from the *current*
companies/domains tables. update-domains.py can add/modify rows while this
script runs; the in-flight company is not interrupted. The pick order is:

  1. Companies never enumerated (NULL last_enum), by companies.run_schedule:
     DAILY, then WEEKLY, BIWEEKLY, MONTHLY, QUARTERLY, SEMI_ANNUALLY,
     ANNUALLY; within a schedule, higher company id first.
  2. Then companies already enumerated, oldest last_enum first (the schedule
     does not affect this order).

Companies whose run_schedule is NEVER, NULL or any other value are never
picked automatically; they run only when named on the command line.
Schedule values are compared exactly as stored.

Domains are passed to amass with the company's root domain first (the row
with public.domains.is_root set), then the rest alphabetically. A company with
no root domain flagged runs in alphabetical order, with a warning.

Ctrl-C: stop the enum container, docker compose stop engine (engine only),
do not write last_enum, write a report of what was collected so far to
./report/<companyID>-<companyName>-partial.xlsx, then exit. Ctrl-C again
while that report is being written abandons it and exits at once. A Ctrl-C
after a company has finished enumerating lets its normal report complete
first; a Ctrl-C while waiting for work just exits. SIGTERM is handled the
same way.

Run from the compose directory, with sudo if your user cannot talk to Docker:

    cd ~/amass-docker-compose
    sudo python3 ./enum-companies.py
    sudo python3 ./enum-companies.py 28656            # that company first
    sudo python3 ./enum-companies.py 28656,411,9012   # those companies, in order

Companies named on the command line run first, in the order given, whatever
their run_schedule (NEVER included), and then normal selection continues.

After each successful enumeration an Excel report is written to
./report/<companyID>-<companyName>.xlsx (tabs: Assets, IP's, TP Links,
Unknown Domains, Tech-Stack, Scope Domains, Scope Netblocks, Scope ASNs,
Scope IPs). A failed report is logged and the queue continues.

The four Scope tabs are the session scope amass ended the run with: the seed
domains plus every domain, netblock, ASN and IP address it associated with
them. amass keeps the scope only in the engine's memory, so enum is run with
-scope-json, which prints it as one stdout line just before the session ends;
that line is captured (not shown on the console) and saved to
./report/scope/<companyID>.json, where --report-only and report-enumerated.py
find it later. An interrupted run's scope goes to <companyID>-partial.json
for its partial report. Companies enumerated before this was added, or runs
killed outright, have no saved scope: their Scope tabs say so.

Every tab is filled by one of the assetdb functions in
docs/hypermass_functions.sql (fqdn_by_domains, ips_by_domains,
tplinks_by_domain, other_domains_by_inscope_domains, techstack_by_domains),
which must exist in the database. The five tab queries run in parallel, each
on its own database connection, so a report takes about as long as its
slowest tab.

Reports only, no enumeration (no Docker needed):

    python3 ./enum-companies.py --report-only 28656
    python3 ./enum-companies.py --report-only 28656,411,9012

In --report-only mode, Ctrl-C lets the current report finish and skips the
rest; Ctrl-C again abandons the current report too.

Reports need the system xlsxwriter package:  sudo apt install python3-xlsxwriter

A report that has not finished within 15 minutes (REPORT_TIME_LIMIT_SECONDS)
is cancelled -- including any query still running on the database server --
and no file is written for that company; the script carries on as normal.
Likewise, if any tab has more rows than an Excel sheet can hold (1,048,575
plus the header), the report is cancelled and no file is written.

If amass exits with an error for a company, the script stops instead of
moving on: the engine is stopped, last_enum is left unchanged, the ids that
had not run yet are printed so the run can be resumed, and the script exits
with amass's exit status. Re-run the command amass ran without -silent to
see its error message (enum -silent discards it).
"""

from __future__ import annotations

import datetime
import decimal
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Optional

import psycopg2
import psycopg2.errors
import psycopg2.extensions
import psycopg2.extras

# Wait for the server in Python (select) rather than inside libpq, so a second
# Ctrl-C can interrupt a long report query: wait_select turns the
# KeyboardInterrupt raised by on_sigint into a server-side cancel.
psycopg2.extensions.set_wait_callback(psycopg2.extras.wait_select)

DB = dict(
    host="192.168.1.125",
    port=5432,
    dbname="assetdb",
    user="postgres",
    password="CHANGE_ME",
    # TCP keepalives: detect a dropped/half-open connection and keep NAT and
    # firewall state alive while the bookkeeping connection sits idle through a
    # long run_enum(). Defense in depth alongside autocommit + reconnect below.
    keepalives=1,
    keepalives_idle=30,
    keepalives_interval=10,
    keepalives_count=5,
)

# Always the directory you launched from.
COMPOSE_DIR = os.getcwd()

# Root already has docker.sock; otherwise prefix sudo (TTY inherited).
DOCKER = ["docker"] if os.geteuid() == 0 else ["sudo", "-A", "docker"] if os.environ.get("SUDO_ASKPASS") else ["sudo", "docker"]

# docker compose / the kernel often deliver Ctrl-C to the child only.
# Python never sets _stop; wait() returns 130 and we used to start the next
# company. Treat these as a full abort.
INTERRUPT_CODES = {130, 137, 143, -2, -9, -15}

# companies.run_schedule values that are picked automatically, highest priority
# first. NEVER, NULL and any value not listed here are never picked
# automatically (only when named on the command line). Values are compared
# exactly as stored in the table.
RUN_SCHEDULE_PRIORITY = [
    "DAILY",
    "WEEKLY",
    "BIWEEKLY",
    "MONTHLY",
    "QUARTERLY",
    "SEMI_ANNUALLY",
    "ANNUALLY",
]

# First Ctrl-C: stop enumerating (the in-flight company's report is still written).
_stop = False
# Second Ctrl-C: also abandon the report being written, and exit.
_abort = False
# True while write_report() is building a workbook; a second Ctrl-C then
# raises KeyboardInterrupt to stop it immediately.
_in_report = False
_child: Optional[subprocess.Popen] = None
# Session scope from the most recent run_enum() (the -scope-json line), or
# None if amass did not print one.
last_scope: Optional[dict] = None
# Company ids that failed this process; do not hammer the same row.
_failed: set[int] = set()


def connect(autocommit: bool = False):
    conn = psycopg2.connect(**DB)
    # autocommit=True keeps the connection out of the "idle in transaction"
    # state after a SELECT. A connection left idle in transaction across a long
    # run_enum() is exactly what the server's idle_in_transaction_session_timeout
    # terminates -- which is what crashed the queue mid-run. The report
    # connection keeps the default (False): its server-side named cursors need a
    # real transaction to stream rows.
    conn.autocommit = autocommit
    return conn


def _conn_alive(conn) -> bool:
    """True if conn can run a trivial query right now."""
    if conn is None or conn.closed:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        return True
    except psycopg2.Error:
        return False


def reconnect(conn, autocommit: bool = True):
    """Return a live connection, reopening if the current one has died.

    The bookkeeping connection sits idle for the whole of run_enum() -- which,
    for a large company, can outlast the server's idle session timeout or a
    network idle reaper. Validate it and transparently reopen rather than let
    the next query crash the whole queue.
    """
    if _conn_alive(conn):
        return conn
    print("  database connection was dropped; reconnecting")
    try:
        if conn is not None:
            conn.close()
    except psycopg2.Error:
        pass
    return connect(autocommit=autocommit)


def parse_requested_ids(argv: list[str]) -> list[int]:
    """[] = no override. Exits 2 if any token is not a positive integer.

    Accepts one id, a comma-separated list, or several shell words, so all
    of these mean the same thing:

        enum-companies.py 28656,411,9012
        enum-companies.py 28656, 411, 9012
        enum-companies.py 28656 411 9012

    Order is preserved. Repeats are dropped, first occurrence wins.
    """
    argv = [a for a in argv if a != "--report-only"]
    if len(argv) == 1:
        return []
    tokens = [t for t in re.split(r"[,\s]+", " ".join(argv[1:])) if t]
    if not tokens:
        print(
            "usage: enum-companies.py [--report-only] [company_id[,company_id...]]",
            file=sys.stderr,
        )
        sys.exit(2)

    ids: list[int] = []
    seen: set[int] = set()
    for token in tokens:
        if not re.fullmatch(r"[1-9][0-9]*", token):
            print(
                f"error: arguments must be positive integers, got {token!r}",
                file=sys.stderr,
            )
            sys.exit(2)
        cid = int(token)
        if cid in seen:
            print(f"note: company id {cid} listed more than once; keeping the first")
            continue
        seen.add(cid)
        ids.append(cid)
    return ids


def existing_company_ids(conn, ids: list[int]) -> set[int]:
    """Which of these ids are actually in companies right now."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM public.companies WHERE id = ANY(%s)",
            (ids,),
        )
        return {r[0] for r in cur.fetchall()}


def company_by_id(conn, company_id: int) -> Optional[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT c.id, c.name, c.last_enum, c.run_schedule::text AS run_schedule
            FROM public.companies c
            WHERE c.id = %s
            """,
            (company_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def pick_next(conn) -> Optional[dict]:
    """One row from the live table. Re-run after every company.

    Never-enumerated companies first, by run_schedule priority
    (RUN_SCHEDULE_PRIORITY) and then higher id; then already-enumerated
    companies, oldest last_enum first. Only companies with domains and a
    schedule in RUN_SCHEDULE_PRIORITY are considered, so NEVER, NULL and
    unknown schedules are skipped. Companies that failed in this process
    (_failed) are skipped until the next pass.
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT c.id, c.name, c.last_enum, c.run_schedule::text AS run_schedule
            FROM public.companies c
            WHERE EXISTS (
                SELECT 1 FROM public.domains d WHERE d.company_id = c.id
            )
              AND c.run_schedule::text = ANY(%(schedules)s::text[])
              AND NOT (c.id = ANY(%(failed)s::bigint[]))
            ORDER BY
                (c.last_enum IS NULL) DESC,
                CASE WHEN c.last_enum IS NULL
                     THEN array_position(%(schedules)s::text[], c.run_schedule::text) END,
                CASE WHEN c.last_enum IS NULL THEN c.id END DESC,
                c.last_enum ASC NULLS LAST,
                c.id DESC
            LIMIT 1
            """,
            {"schedules": RUN_SCHEDULE_PRIORITY, "failed": sorted(_failed)},
        )
        row = cur.fetchone()
        return dict(row) if row else None


def schedule_summary(conn) -> Optional[str]:
    """One line describing run_schedule coverage, or None if the column is missing."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    count(*) FILTER (WHERE run_schedule::text = ANY(%(s)s::text[])),
                    count(*) FILTER (WHERE run_schedule::text = 'NEVER'),
                    count(*) FILTER (WHERE run_schedule IS NULL
                                        OR NOT (run_schedule::text = ANY(%(s)s::text[])
                                                OR run_schedule::text = 'NEVER'))
                FROM public.companies
                """,
                {"s": RUN_SCHEDULE_PRIORITY},
            )
            scheduled, never, unknown = cur.fetchone()
    except psycopg2.errors.UndefinedColumn:
        return None
    line = f"run schedules: {scheduled} scheduled, {never} NEVER"
    if unknown:
        line += f", {unknown} NULL/unknown (treated as NEVER)"
    return line


def domains_for(conn, company_id: int) -> list[str]:
    """The company's domains, root domain(s) first, then the rest alphabetically.

    The order is fixed (domain_id breaks any tie), because mark_enumerated()
    compares a fresh read against the snapshot taken before the run.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT domain
            FROM public.domains
            WHERE company_id = %s
            ORDER BY is_root DESC, domain, domain_id
            """,
            (company_id,),
        )
        return [r[0] for r in cur.fetchall()]


def root_domain_count(conn, company_id: int) -> int:
    """How many of the company's domains are flagged is_root."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM public.domains WHERE company_id = %s AND is_root",
            (company_id,),
        )
        return cur.fetchone()[0]


def warn_root_domains(conn, company_id: int, name: str, domains: list[str]) -> None:
    """Note when the root-first ordering could not do what it is meant to."""
    roots = root_domain_count(conn, company_id)
    if roots == 0:
        print(f"[{company_id}] {name}: warning: no domain is flagged is_root; "
              "domains are in alphabetical order")
    elif roots > 1:
        print(f"[{company_id}] {name}: warning: {roots} domains are flagged is_root; "
              f"all are listed first ({', '.join(domains[:roots])})")


def mark_enumerated(conn, company_id: int, snapshot: list[str], picked_last_enum) -> bool:
    """Write last_enum only if this company was not retargeted mid-run."""
    current = domains_for(conn, company_id)
    if current != snapshot:
        print(
            f"  domain list changed during run ({len(snapshot)} -> {len(current)} domains); "
            "not setting last_enum"
        )
        return False
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE public.companies
            SET last_enum = NOW()
            WHERE id = %s
              AND last_enum IS NOT DISTINCT FROM %s
            """,
            (company_id, picked_last_enum),
        )
        ok = cur.rowcount == 1
    conn.commit()
    if not ok:
        print("  last_enum changed during run; not overwriting")
    return ok


def stop_engine() -> None:
    subprocess.run(
        DOCKER + ["compose", "stop", "engine"],
        cwd=COMPOSE_DIR,
        check=False,
    )


def _signal_child(sig: int = signal.SIGINT) -> None:
    if _child is None or _child.poll() is not None:
        return
    try:
        os.killpg(_child.pid, sig)
    except OSError:
        try:
            _child.send_signal(sig)
        except OSError:
            pass


def on_sigint(signum, frame):
    """First Ctrl-C: stop, but still write the report. Second: abandon it too."""
    global _stop, _abort
    if not _stop:
        _stop = True
        print("\nCtrl-C: stopping. A company in progress still gets a report; "
              "press Ctrl-C again to skip it.")
        _signal_child(signal.SIGINT)
        return
    if not _abort:
        _abort = True
        print("\nCtrl-C again: abandoning the report and exiting")
    # Do not leave amass shutting down in the background.
    _signal_child(signal.SIGKILL)
    if _in_report:
        raise KeyboardInterrupt


# enum -scope-json prints the session scope as one stdout line starting with
# this marker (internal/enum/scope_json.go).
SCOPE_MARKER = "HYPERMASS_SCOPE "


def _read_enum_stdout(pipe) -> None:
    """Pass amass's stdout through to the console, except the -scope-json line,
    which is kept in last_scope instead of being printed."""
    global last_scope
    for raw in iter(pipe.readline, b""):
        line = raw.decode("utf-8", errors="replace")
        if line.startswith(SCOPE_MARKER):
            try:
                scope = json.loads(line[len(SCOPE_MARKER):])
                if isinstance(scope, dict):
                    last_scope = scope
            except ValueError:
                pass
            continue
        sys.stdout.write(line)
        sys.stdout.flush()
    pipe.close()


def run_enum(domains: list[str]) -> int:
    global _child, last_scope
    last_scope = None
    # -T: do not give the container the controlling TTY. Otherwise
    # `compose run` becomes the foreground pgroup and eats Ctrl-C;
    # this script never sees SIGINT and starts the next company.
    # start_new_session: child gets its own process group so a TTY
    # SIGINT cannot land on docker. Script is sudo python3 (euid 0),
    # so docker does not need a sudo TTY.
    cmd = DOCKER + [
        "compose",
        "run",
        "--rm",
        "-T",
        "enum",
        "-active",
        # Allow -active with no active_proxy configured: send active traffic
        # over the default egress instead of refusing the run. Remove this if
        # an active_proxy is ever configured and the proxy must be enforced.
        "-active-strict=false",
       # "-rigid",
        "-silent",
        # Print the session scope at the end (captured by _read_enum_stdout).
        "-scope-json",
        "-d",
        ",".join(domains),
    ]
    _child = subprocess.Popen(
        cmd,
        cwd=COMPOSE_DIR,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        start_new_session=True,
    )
    reader = threading.Thread(target=_read_enum_stdout, args=(_child.stdout,),
                              name="enum-stdout", daemon=True)
    reader.start()
    try:
        while True:
            try:
                return _child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                if _stop:
                    _signal_child(signal.SIGINT)
                    try:
                        _child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        _signal_child(signal.SIGKILL)
                        _child.wait()
                    return 130
    finally:
        # The scope line is the last thing amass prints; let the reader
        # finish with it once amass has exited.
        reader.join(10)
        _child = None


# ---------------------------------------------------------------------------
# Excel report
# ---------------------------------------------------------------------------
#
# After each successful enumeration a workbook is written to
# <compose dir>/report/<companyID>-<companyName>.xlsx with five query tabs,
# each filled by one of the assetdb functions in docs/hypermass_functions.sql
# with the company's seed domains, then four Scope tabs filled from the
# session scope saved in report/scope/ (see save_scope). The domain list is always passed as a query
# parameter, never pasted into SQL text. An interrupted enumeration writes the
# same workbook as <companyID>-<companyName>-partial.xlsx.
#
# Needs xlsxwriter from the system Python:  sudo apt install python3-xlsxwriter
# If it is missing, or a report fails for any other reason, the error is
# printed and enumeration continues.

REPORT_DIR = os.path.join(COMPOSE_DIR, "report")

EXCEL_MAX_ROWS = 1_048_576          # including the header row
EXCEL_MAX_CELL = 32_767             # characters per cell
FETCH_BATCH = 5_000
# Row batches buffered between the tab query threads and the workbook writer.
# Bounds memory: a query that gets ahead of the writer waits for it.
REPORT_QUEUE_BATCHES = 8
MIN_COL_WIDTH, MAX_COL_WIDTH = 8, 60
WIDTH_SAMPLE_ROWS = 2_000           # rows inspected when sizing columns
US_DATETIME = "mm/dd/yyyy hh:mm:ss"
US_DATE = "mm/dd/yyyy"
# A report still running after this long is cancelled and skipped. For the
# largest companies the data is too big to be useful in a workbook anyway.
REPORT_TIME_LIMIT_SECONDS = 15 * 60

# Outcome of the most recent write_report() call: "written", "timeout",
# "too_large" (a tab exceeds Excel's row limit), "abandoned" (Ctrl-C),
# "failed" or "skipped". Lets callers such as
# report-enumerated.py tell a time-limit cancellation from a real failure.
last_report_outcome: Optional[str] = None

ASSETS_SQL = """
SELECT *
FROM fqdn_by_domains(%s)
ORDER BY created_at DESC
"""

IPS_SQL = """
SELECT * FROM ips_by_domains(%s)
"""

TP_LINKS_SQL = """
SELECT *
FROM tplinks_by_domain(%s)
ORDER BY other_domain, evidence
"""

UNKNOWN_DOMAINS_SQL = """
SELECT domain
FROM other_domains_by_inscope_domains(%s)
ORDER BY domain
"""

TECH_STACK_SQL = """
SELECT *
FROM techstack_by_domains(%s)
ORDER BY fqdn, port
"""

# (sheet name, query); every query takes the domain CSV as its one parameter.
REPORT_SHEETS = [
    ("Assets", ASSETS_SQL),
    ("IP's", IPS_SQL),
    ("TP Links", TP_LINKS_SQL),
    ("Unknown Domains", UNKNOWN_DOMAINS_SQL),
    ("Tech-Stack", TECH_STACK_SQL),
]

# Session scope tabs, after the query tabs: (sheet name, scope JSON key,
# column header). Filled from the scope captured by -scope-json, not from a
# query.
SCOPE_SHEETS = [
    ("Scope Domains", "fqdn", "domain"),
    ("Scope Netblocks", "netblock", "netblock"),
    ("Scope ASNs", "autonomoussystem", "asn"),
    ("Scope IPs", "ipaddress", "ip_address"),
]

SCOPE_DIR = os.path.join(REPORT_DIR, "scope")


def scope_path(company_id: int, partial: bool = False) -> str:
    return os.path.join(SCOPE_DIR, f"{company_id}{'-partial' if partial else ''}.json")


def save_scope(company_id: int, scope: Optional[dict], partial: bool = False) -> None:
    """Save the run's session scope for this company's reports.

    Written after every run, so the file always describes the latest one: a
    run whose scope was not captured saves a record saying so, rather than
    leaving an older run's scope to be reported as this one's.
    """
    record = dict(scope) if scope else {"errors": {"*": "amass did not print the session scope"}}
    record["company_id"] = company_id
    record["captured_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    path = scope_path(company_id, partial)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        os.makedirs(SCOPE_DIR, exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(record, f)
        os.replace(tmp, path)
        ids = _invoking_ids()
        if ids:
            for p in (REPORT_DIR, SCOPE_DIR, path):
                os.chown(p, *ids)
    except OSError as e:
        print(f"  could not save the session scope: {e}")
        try:
            os.unlink(tmp)
        except OSError:
            pass


def load_scope(company_id: int, partial: bool = False) -> Optional[dict]:
    """The saved session scope, or None if there is none (or it is unreadable)."""
    try:
        with open(scope_path(company_id, partial)) as f:
            scope = json.load(f)
        return scope if isinstance(scope, dict) else None
    except (OSError, ValueError):
        return None


def _write_scope_sheets(sheets, scope: Optional[dict]) -> None:
    """Fill the Scope tabs. A type amass could not read, or a run with no
    saved scope, gets a one-line note instead of an empty tab that would look
    like 'nothing in scope'."""
    errors = (scope or {}).get("errors") or {}
    for sheet, (_, key, column) in zip(sheets, SCOPE_SHEETS):
        sheet.header([column])
        if scope is None:
            sheet.add([["(session scope not captured for this run)"]])
        elif key in errors or "*" in errors:
            sheet.add([[f"(session scope not captured: {errors.get(key) or errors.get('*')})"]])
        else:
            values = scope.get(key) or []
            for i in range(0, len(values), FETCH_BATCH):
                sheet.add([[v] for v in values[i:i + FETCH_BATCH]])  # may raise ReportTooLarge
        sheet.finish()
        print(f"  {sheet.name}: {sheet.rows:,} rows")


_ILLEGAL_FILENAME = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')


class ReportAborted(Exception):
    pass


class ReportTimedOut(Exception):
    pass


class ReportTooLarge(Exception):
    """A tab has more rows than an Excel sheet can hold."""

    def __init__(self, sheet: str):
        super().__init__(sheet)
        self.sheet = sheet


def _time_limit_text() -> str:
    """REPORT_TIME_LIMIT_SECONDS for messages: '15 minutes', or seconds if uneven."""
    secs = REPORT_TIME_LIMIT_SECONDS
    if secs % 60 == 0:
        return f"{secs // 60} minute{'s' if secs != 60 else ''}"
    return f"{secs} seconds"


def report_filename(company_id: int, company_name: str, partial: bool = False) -> str:
    """'12-FortifyData.xlsx': illegal characters removed, whitespace -> '_'.

    partial=True gives '12-FortifyData-partial.xlsx', for an interrupted run, so
    it never replaces a complete report from an earlier run.
    """
    suffix = "-partial" if partial else ""
    name = _ILLEGAL_FILENAME.sub("", company_name or "")
    name = re.sub(r"\s+", "_", name.strip())
    name = name.strip("._")
    # Keep the whole name well under the 255-byte filesystem limit.
    while len(f"{company_id}-{name}{suffix}.xlsx".encode()) > 200:
        name = name[:-1]
    return f"{company_id}-{name}{suffix}.xlsx" if name else f"{company_id}{suffix}.xlsx"


def _invoking_ids():
    """uid/gid of the user behind sudo, so report files are not owned by root."""
    try:
        return int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return None


def _cell(value):
    """Convert a database value to something Excel stores faithfully."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return ", ".join("" if v is None else str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (bytes, memoryview)):
        return bytes(value).hex()
    if isinstance(value, datetime.datetime) and value.tzinfo is not None:
        return value.astimezone().replace(tzinfo=None)
    if isinstance(value, (bool, int, float, datetime.datetime, datetime.date)):
        return value
    return str(value)


def _display_len(value) -> int:
    if value is None:
        return 0
    if isinstance(value, datetime.datetime):
        return 19
    if isinstance(value, datetime.date):
        return 10
    return max((len(line) for line in str(value).splitlines()), default=0)


class _SheetWriter:
    """Writes one tab's rows into its worksheet, in row order.

    The worksheets are created up front, in REPORT_SHEETS order, so the tab
    order of the workbook does not depend on which query finishes first. Rows
    for different sheets may arrive interleaved; each sheet still receives its
    own rows in order, which is all constant_memory mode requires.
    """

    def __init__(self, book, name, fmt):
        self.ws = book.add_worksheet(name)
        self.name = name
        self.fmt = fmt
        self.rows = 0
        self.ncols = 0
        self.widths: list[int] = []

    def header(self, headers):
        self.ws.write_row(0, 0, headers, self.fmt["header"])
        self.ncols = len(headers)
        self.widths = [len(h) for h in headers]

    def add(self, batch):
        """Append a batch of rows. Raises ReportTooLarge on the first row that
        would not fit in a sheet (EXCEL_MAX_ROWS, header included)."""
        ws, fmt, widths = self.ws, self.fmt, self.widths
        for record in batch:
            if self.rows + 1 >= EXCEL_MAX_ROWS:
                # One row more than the sheet can hold: the whole report is
                # cancelled rather than written incomplete.
                raise ReportTooLarge(self.name)
            self.rows += 1
            row = self.rows
            for col, raw in enumerate(record):
                value = _cell(raw)
                if value is None:
                    continue
                if isinstance(value, datetime.datetime):
                    ws.write_datetime(row, col, value, fmt["datetime"])
                elif isinstance(value, datetime.date):
                    ws.write_datetime(row, col, datetime.datetime.combine(value, datetime.time()), fmt["date"])
                elif isinstance(value, bool):
                    ws.write_boolean(row, col, value)
                elif isinstance(value, (int, float)):
                    ws.write_number(row, col, value)
                else:
                    if len(value) > EXCEL_MAX_CELL:
                        value = value[: EXCEL_MAX_CELL - 1] + "…"
                    ws.write_string(row, col, value)
                if row <= WIDTH_SAMPLE_ROWS:
                    widths[col] = max(widths[col], _display_len(value))

    def finish(self):
        self.ws.freeze_panes(1, 0)
        self.ws.autofilter(0, 0, max(self.rows, 1), max(self.ncols - 1, 0))
        for col, w in enumerate(self.widths):
            # +2 leaves room for the autofilter arrow.
            self.ws.set_column(col, col, min(max(w + 2, MIN_COL_WIDTH), MAX_COL_WIDTH))


class _TabQuery(threading.Thread):
    """Runs one tab's query on its own connection and streams its rows to the
    workbook writer through a shared queue, as (tab index, kind, payload):
    ("columns", [names]), then ("rows", batch) as many times as needed, then
    ("end", None) -- or ("error", exception) if the query fails.

    The writer stops a report by setting `stop` and calling cancel(), which
    cancels the query on the server; the thread then exits without sending
    anything more.
    """

    def __init__(self, index, sheet, query, csv, out, stop):
        super().__init__(name=f"report-tab-{index}", daemon=True)
        self.index, self.sheet, self.query, self.csv = index, sheet, query, csv
        self.out, self.stop = out, stop
        self.conn = None
        self._conn_lock = threading.Lock()

    def cancel(self):
        """Cancel this tab's query on the server, if one is running."""
        with self._conn_lock:
            if self.conn is not None and not self.conn.closed:
                try:
                    self.conn.cancel()
                except Exception:
                    pass

    def _send(self, kind, payload=None) -> bool:
        # Wait while the writer catches up, but give up once the report stops.
        while not self.stop.is_set():
            try:
                self.out.put((self.index, kind, payload), timeout=0.5)
                return True
            except queue.Full:
                continue
        return False

    def run(self):
        conn = None
        try:
            conn = connect()
            with self._conn_lock:
                self.conn = conn
            if self.stop.is_set():
                return
            with conn.cursor() as cur:
                cur.execute("SET jit = off")
            # Server-side cursor: rows arrive in batches, not all at once.
            with conn.cursor(name=f"report_{self.index}") as cur:
                cur.itersize = FETCH_BATCH
                cur.execute(self.query, (self.csv,))
                # A server-side cursor only knows its columns after the first fetch.
                batch = cur.fetchmany(FETCH_BATCH)
                if not self._send("columns", [d[0] for d in cur.description]):
                    return
                while batch:
                    if not self._send("rows", batch):
                        return
                    batch = cur.fetchmany(FETCH_BATCH)
            self._send("end")
        except Exception as e:
            self._send("error", e)
        finally:
            # Under the lock, so cancel() never touches a connection being closed.
            with self._conn_lock:
                self.conn = None
                if conn is not None:
                    try:
                        conn.rollback()
                        conn.close()
                    except Exception:
                        pass


def _stop_tab_queries(tabs, stop) -> None:
    """Stop every tab query thread, cancelling queries still running on the server.

    Cancels repeatedly until the threads exit, so a query that was just
    starting when the first cancel went out is cancelled too.
    """
    stop.set()
    give_up = time.monotonic() + 30
    while any(t.is_alive() for t in tabs) and time.monotonic() < give_up:
        for t in tabs:
            if t.is_alive():
                t.cancel()
        for t in tabs:
            t.join(0.2)


def write_report(company_id: int, company_name: str, domains: list[str],
                 partial: bool = False) -> Optional[str]:
    """Build the workbook for one company. Returns its path, or None on failure.

    The Scope tabs come from the scope saved by save_scope() (the -partial
    one for a partial report).

    A first Ctrl-C does not stop it (an interrupted company still gets its
    report); a second one abandons it, cancelling any query in progress.
    partial=True names the file <id>-<name>-partial.xlsx.

    The five tab queries run in parallel, each on its own connection
    (_TabQuery); this thread writes their rows into the workbook as they
    arrive, so out-of-order completion does not matter.

    A report not finished within REPORT_TIME_LIMIT_SECONDS is cancelled: a
    timer cancels every tab query still running on the server, and the writer
    stops. A tab too large for Excel, a second Ctrl-C, or an error in any tab
    likewise stops all of them. No file is written and the caller carries on.
    """
    global _in_report, last_report_outcome
    last_report_outcome = "skipped"
    try:
        import xlsxwriter
    except ImportError:
        print("  report skipped: xlsxwriter is not installed "
              "(sudo apt install python3-xlsxwriter)")
        return None
    if _abort:
        print("  report skipped (Ctrl-C)")
        return None

    csv = ",".join(domains)
    final_path = os.path.join(REPORT_DIR, report_filename(company_id, company_name, partial))
    tmp_path = os.path.join(REPORT_DIR, f".{os.path.basename(final_path)}.{os.getpid()}.tmp")
    started = time.monotonic()
    deadline = started + REPORT_TIME_LIMIT_SECONDS
    timer = None
    timed_out = threading.Event()
    stop = threading.Event()
    tabs: list[_TabQuery] = []
    try:
        _in_report = True
        os.makedirs(REPORT_DIR, exist_ok=True)
        ids = _invoking_ids()
        if ids:
            os.chown(REPORT_DIR, *ids)

        book = xlsxwriter.Workbook(tmp_path, {
            "constant_memory": True,       # stream rows to disk
            "strings_to_urls": False,      # no hyperlinks
            "strings_to_formulas": False,  # a value starting with '=' stays text
            "strings_to_numbers": False,
        })
        fmt = {
            "header": book.add_format({"bold": True}),
            "datetime": book.add_format({"num_format": US_DATETIME}),
            "date": book.add_format({"num_format": US_DATE}),
        }
        try:
            # Sheets first, in tab order; then all tab queries at once.
            sheets = [_SheetWriter(book, sheet, fmt) for sheet, _ in REPORT_SHEETS]
            scope_sheets = [_SheetWriter(book, sheet, fmt) for sheet, _, _ in SCOPE_SHEETS]
            _write_scope_sheets(scope_sheets, load_scope(company_id, partial))
            out: queue.Queue = queue.Queue(maxsize=REPORT_QUEUE_BATCHES)
            tabs = [_TabQuery(i, sheet, query, csv, out, stop)
                    for i, (sheet, query) in enumerate(REPORT_SHEETS)]

            # At the deadline, cancel every tab query still running on the
            # server. connection.cancel() is safe to call from another thread.
            def _on_deadline():
                timed_out.set()
                stop.set()
                for t in tabs:
                    t.cancel()
            timer = threading.Timer(max(0.0, deadline - time.monotonic()), _on_deadline)
            timer.daemon = True
            timer.start()

            for t in tabs:
                t.start()

            pending = set(range(len(tabs)))
            while pending:
                if _abort:
                    raise ReportAborted()
                if timed_out.is_set() or time.monotonic() >= deadline:
                    raise ReportTimedOut()
                try:
                    index, kind, payload = out.get(timeout=0.5)
                except queue.Empty:
                    continue
                sheet = sheets[index]
                if kind == "columns":
                    sheet.header(payload)
                elif kind == "rows":
                    sheet.add(payload)          # may raise ReportTooLarge
                elif kind == "end":
                    sheet.finish()
                    pending.discard(index)
                    # Tabs finish in any order; the time is since the report started.
                    print(f"  {sheet.name}: {sheet.rows:,} rows in {time.monotonic() - started:.1f}s")
                elif kind == "error":
                    raise payload
        finally:
            # Stop and cancel any tab query still running before closing.
            _stop_tab_queries(tabs, stop)
            book.close()
        os.replace(tmp_path, final_path)
        if ids:
            os.chown(final_path, *ids)
        print(f"  report written: {final_path} ({time.monotonic() - started:.1f}s)")
        last_report_outcome = "written"
        return final_path
    except (ReportAborted, KeyboardInterrupt):
        print("  report abandoned (Ctrl-C)")
        last_report_outcome = "abandoned"
        return None
    except ReportTimedOut:
        print(f"  report canceled: not finished within {_time_limit_text()}")
        last_report_outcome = "timeout"
        return None
    except ReportTooLarge as e:
        print(f"  report canceled: {e.sheet} has more than "
              f"{EXCEL_MAX_ROWS - 1:,} rows (Excel's limit)")
        last_report_outcome = "too_large"
        return None
    except Exception as e:
        # A query cancelled by a second Ctrl-C, or by the time limit, surfaces
        # here as QueryCanceled (raised by its tab thread, passed on here).
        if _abort:
            print("  report abandoned (Ctrl-C)")
            last_report_outcome = "abandoned"
        elif timed_out.is_set():
            print(f"  report canceled: not finished within {_time_limit_text()}")
            last_report_outcome = "timeout"
        else:
            print(f"  report failed: {type(e).__name__}: {str(e).strip()}")
            last_report_outcome = "failed"
        return None
    finally:
        _in_report = False
        if timer is not None:
            timer.cancel()
        # Normally already done above; this covers a failure before then.
        _stop_tab_queries(tabs, stop)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def run_reports_only(conn, ids: list[int]) -> int:
    """--report-only: build reports for these companies without enumerating."""
    found = existing_company_ids(conn, ids)
    failures = 0
    for cid in ids:
        if _stop:
            break
        if cid not in found:
            print(f"company id {cid} not found; skipping")
            failures += 1
            continue
        company = company_by_id(conn, cid)
        domains = domains_for(conn, cid)
        if not domains:
            print(f"[{cid}] {company['name']}: no domains; skipping")
            failures += 1
            continue
        warn_root_domains(conn, cid, company["name"], domains)
        print(f"[{cid}] {company['name']}: report for {len(domains)} domain(s)")
        if write_report(cid, company["name"], domains) is None:
            failures += 1
    return 1 if failures else 0


def main() -> int:
    global _stop
    report_only = "--report-only" in sys.argv[1:]
    requested = parse_requested_ids(sys.argv)

    if report_only:
        if not requested:
            print("usage: enum-companies.py --report-only company_id[,company_id...]",
                  file=sys.stderr)
            return 2
        signal.signal(signal.SIGINT, on_sigint)
        signal.signal(signal.SIGTERM, on_sigint)
        print(f"report dir:  {REPORT_DIR}")
        conn = connect(autocommit=True)
        try:
            return run_reports_only(conn, requested)
        finally:
            conn.close()

    print(f"compose dir: {COMPOSE_DIR}")
    print(f"report dir:  {REPORT_DIR}")
    print(f"docker cmd:  {' '.join(DOCKER)}")

    signal.signal(signal.SIGINT, on_sigint)
    signal.signal(signal.SIGTERM, on_sigint)

    conn = connect(autocommit=True)

    summary = schedule_summary(conn)
    if summary is None:
        print("error: public.companies has no run_schedule column; "
              "load the companies table with the current CSV format first",
              file=sys.stderr)
        conn.close()
        return 2
    print(summary)

    # Requested ids run first, in the order given; then normal selection.
    # Checked once up front so a typo in a long list is reported now rather
    # than an hour from now, but each row is re-read when its turn arrives.
    queue: list[int] = []
    if requested:
        found = existing_company_ids(conn, requested)
        missing = [c for c in requested if c not in found]
        if missing:
            print(
                "company id(s) not found, skipping: "
                + ", ".join(str(c) for c in missing)
            )
        queue = [c for c in requested if c in found]
        if queue:
            print(
                f"requested queue ({len(queue)}): "
                + ", ".join(str(c) for c in queue)
            )
        else:
            print("no requested company ids remain; continuing with normal selection")

    exit_code = 0
    try:
        while not _stop:
            # Validate (and if needed reopen) the connection at the top of every
            # iteration: write_report and the idle waits below can outlast the
            # server/network idle timeout just as run_enum() can.
            conn = reconnect(conn)
            company = None
            while queue and company is None:
                qid = queue.pop(0)
                company = company_by_id(conn, qid)
                if company is None:
                    print(f"company id {qid} no longer exists; skipping")
            if company is None:
                company = pick_next(conn)
            if company is None:
                if _failed:
                    print(
                        f"No remaining companies this pass "
                        f"({len(_failed)} failed). Retrying in 60s..."
                    )
                    _failed.clear()
                else:
                    print("No companies to enumerate (none with domains and a run "
                          "schedule other than NEVER). Waiting 60s...")
                for _ in range(60):
                    if _stop:
                        break
                    time.sleep(1)
                continue

            cid = company["id"]
            name = company["name"]
            snapshot = domains_for(conn, cid)
            if not snapshot:
                print(f"[{cid}] {name}: no domains, skipping")
                _failed.add(cid)
                continue

            warn_root_domains(conn, cid, name, snapshot)
            schedule = company["run_schedule"]
            if schedule not in RUN_SCHEDULE_PRIORITY:
                print(f"[{cid}] {name}: run_schedule is {schedule or 'NULL'}; "
                      "running because it was named on the command line")
            print(
                f"[{cid}] {name}: {','.join(snapshot)}  "
                f"last_enum={company['last_enum']!s}  run_schedule={schedule}"
            )
            rc = run_enum(snapshot)
            report_due = False
            if _stop or rc in INTERRUPT_CODES:
                _stop = True
                print(f"[{cid}] {name}: interrupted; last_enum unchanged")
                save_scope(cid, last_scope, partial=True)
                # Still report what was collected before the interruption,
                # after the engine has stopped writing to assetdb.
                print("Stopping engine")
                stop_engine()
                if not _abort:
                    print(f"[{cid}] {name}: writing partial report "
                          "(Ctrl-C again to skip it)")
                    write_report(cid, name, snapshot, partial=True)
                break
            if rc != 0:
                print(f"[{cid}] {name}: enum exited {rc}; last_enum unchanged")
                print(f"Stopping: amass exited with an error ({rc}). Not continuing with "
                      "the next company.")
                print("  To see amass's error message, run the same enumeration without -silent:")
                print(f"    cd {COMPOSE_DIR} && {' '.join(DOCKER)} compose run --rm -T enum "
                      f"-active -active-strict=false -d {','.join(snapshot)}")
                remaining = [cid] + queue
                if cid in requested:
                    print("  To resume the requested ids: "
                          f"sudo python3 {sys.argv[0]} {','.join(str(c) for c in remaining)}")
                exit_code = rc
                break
            else:
                _failed.discard(cid)
                report_due = True
                save_scope(cid, last_scope)
                # run_enum() may have run long enough for the idle bookkeeping
                # connection to be dropped; revive it before writing, and never
                # let a database blip abort the rest of the queue.
                conn = reconnect(conn)
                try:
                    if mark_enumerated(conn, cid, snapshot, company["last_enum"]):
                        print(f"[{cid}] {name}: last_enum updated")
                except psycopg2.Error as e:
                    print(f"[{cid}] {name}: could not update last_enum "
                          f"({type(e).__name__}: {e}); will re-enumerate next pass")
                    conn = reconnect(conn)

            print("Stopping engine (pre-filter reset)")
            stop_engine()
            # Report after the engine has stopped: the queries only read
            # assetdb, and the engine's resources are free by then. A Ctrl-C
            # arriving now still lets this finished company's report complete;
            # only a second Ctrl-C skips it.
            if report_due and not _abort:
                print(f"[{cid}] {name}: writing report")
                write_report(cid, name, snapshot)
            if _stop:
                break
    finally:
        stop_engine()
        conn.close()

    print("Exiting.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
