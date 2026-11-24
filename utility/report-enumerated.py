#!/usr/bin/env python3
"""Write the Excel report for every company that has been enumerated.

Goes through every company whose last_enum is not NULL and writes its report,
exactly as enum-companies.py does after an enumeration. No enumeration is run
and nothing in the database is changed. Reports go to ./report/ and replace
any existing report of the same name.

Up to MAX_CONCURRENT_REPORTS (5) reports are written at the same time, each
in its own worker process; within each report the five tab queries also run
in parallel, so up to 25 database connections are used at once. Each report's
console output is printed as one block when it finishes, so the lines of
different reports do not interleave.

Lives next to enum-companies.py and reuses its report code, so the two always
produce the same workbook. The Scope tabs come from the session scope
enum-companies.py saved in ./report/scope/ after the company's last
enumeration; a company enumerated before that was added has none, and its
Scope tabs say so. Run it from the compose directory (no Docker or
sudo needed, though sudo keeps report files owned by your user):

    cd ~/amass-docker-compose
    python3 ./report-enumerated.py                  # all enumerated companies
    python3 ./report-enumerated.py --skip-existing  # only those without a report yet

--skip-existing lets an interrupted run pick up where it left off. Companies
whose report was canceled by the 15-minute limit have no file, so a
--skip-existing run tries them again.

A report not finished within 15 minutes, or with a tab larger than Excel's
row limit, is canceled and the run moves on to the next company; the summary
counts these separately from failures. Companies canceled for size have no
file either, so --skip-existing tries them again.

Ctrl-C: no new reports start, and the ones in progress finish. Ctrl-C again
abandons the ones in progress too. (SIGTERM sent to this process only stops
new reports from starting; the ones in progress finish, within the 15-minute
limit.)
"""

import contextlib
import importlib.util
import io
import multiprocessing
import os
import signal
import sys
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait

# Reports written at the same time. Each uses one database connection per tab.
MAX_CONCURRENT_REPORTS = 10

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("enum_companies", os.path.join(HERE, "enum-companies.py"))
ec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ec)


# ---------------------------------------------------------------------------
# Worker processes
# ---------------------------------------------------------------------------
# Ctrl-C at the terminal reaches every process in the foreground process
# group, so each worker sees it directly. A worker stays silent (the main
# process does the talking): the first Ctrl-C lets its report finish, the
# second abandons it the same way enum-companies.py does.

def _worker_signal(signum, frame):
    if not ec._stop:
        ec._stop = True
        return
    ec._abort = True
    if ec._in_report:
        raise KeyboardInterrupt


def _worker_init():
    signal.signal(signal.SIGINT, _worker_signal)
    signal.signal(signal.SIGTERM, _worker_signal)


def _report_one(cid, name, domains):
    """Write one company's report in a worker process.

    Returns (outcome, console output); the output is printed by the main
    process as one block.
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ec.write_report(cid, name, domains)
    return ec.last_report_outcome, buf.getvalue()


# ---------------------------------------------------------------------------
# Main process
# ---------------------------------------------------------------------------

def _main_signal(signum, frame):
    if not ec._stop:
        ec._stop = True
        print("\nCtrl-C: no new reports will start; reports in progress will finish. "
              "Press Ctrl-C again to abandon them.", flush=True)
        return
    if not ec._abort:
        ec._abort = True
        print("\nCtrl-C again: abandoning reports in progress", flush=True)


def main() -> int:
    skip_existing = "--skip-existing" in sys.argv[1:]
    signal.signal(signal.SIGINT, _main_signal)
    signal.signal(signal.SIGTERM, _main_signal)
    print(f"report dir:  {ec.REPORT_DIR}")

    conn = ec.connect(autocommit=True)
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM public.companies WHERE last_enum IS NOT NULL ORDER BY id")
        companies = cur.fetchall()
    total = len(companies)
    print(f"{total} enumerated companies, up to {MAX_CONCURRENT_REPORTS} reports at a time")

    written = skipped = canceled = too_large = failed = 0
    started_count = 0
    todo = iter(enumerate(companies, 1))
    running = {}   # future -> (n, cid, name)

    # spawn: workers start as fresh interpreters, so they never inherit this
    # process's open database connection.
    pool = ProcessPoolExecutor(
        max_workers=MAX_CONCURRENT_REPORTS,
        mp_context=multiprocessing.get_context("spawn"),
        initializer=_worker_init,
    )
    try:
        while True:
            # Keep up to MAX_CONCURRENT_REPORTS reports running.
            while len(running) < MAX_CONCURRENT_REPORTS and not ec._stop:
                item = next(todo, None)
                if item is None:
                    break
                n, (cid, name) = item
                if skip_existing and os.path.exists(os.path.join(ec.REPORT_DIR, ec.report_filename(cid, name))):
                    skipped += 1
                    continue
                conn = ec.reconnect(conn)
                domains = ec.domains_for(conn, cid)
                if not domains:
                    print(f"[{n}/{total}] [{cid}] {name}: no domains; skipping")
                    skipped += 1
                    continue
                print(f"[{n}/{total}] [{cid}] {name}: report started for {len(domains)} domain(s)")
                running[pool.submit(_report_one, cid, name, domains)] = (n, cid, name)
                started_count += 1

            if not running:
                break

            done, _ = wait(running, timeout=1, return_when=FIRST_COMPLETED)
            for fut in done:
                n, cid, name = running.pop(fut)
                try:
                    outcome, output = fut.result()
                except Exception as e:
                    outcome, output = "failed", f"  report failed: {type(e).__name__}: {e}\n"
                print(f"[{n}/{total}] [{cid}] {name}:")
                print(output, end="", flush=True)
                if outcome == "written":
                    written += 1
                elif outcome == "timeout":
                    canceled += 1
                elif outcome == "too_large":
                    too_large += 1
                elif outcome == "failed":
                    failed += 1

        if ec._stop:
            print(f"stopped by Ctrl-C after starting {started_count} report(s)")
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        conn.close()

    print(f"done: {written} written, {skipped} skipped, "
          f"{canceled} canceled (time limit), {too_large} canceled (too large), "
          f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
