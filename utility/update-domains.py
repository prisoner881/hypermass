#!/usr/bin/env python3
"""Sync public.companies / public.domains from a company-domain CSV.

CSV columns (header required):
  ID, Name, Domain, Is Root?, Run Schedule

Treats the CSV as source of truth. last_enum is only cleared when a
company is new or its domain set gains a name / changes is_root.
Domain-only removals, name-only edits, and run_schedule-only edits
keep last_enum.

The same domain may belong to more than one company. Each company must
have exactly one row with Is Root? = 1.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict

import psycopg2
from psycopg2.extras import execute_values

DB = {
    "host": "192.168.1.125",
    "port": 5432,
    "dbname": "assetdb",
    "user": "postgres",
    "password": "CHANGE_ME",
}

REQUIRED_COLS = ("ID", "Name", "Domain", "Is Root?", "Run Schedule")


class CsvError(Exception):
    pass


def parse_root(raw: str, line: int) -> bool:
    v = (raw or "").strip()
    if v in ("1", "true", "True", "yes", "YES"):
        return True
    if v in ("0", "false", "False", "no", "NO"):
        return False
    raise CsvError(f"line {line}: Is Root? must be 0 or 1, got {raw!r}")


def load_csv(
    path: str,
) -> tuple[dict[int, str], dict[int, str], dict[int, dict[str, bool]]]:
    """Return (names {id: name}, schedules {id: run_schedule},
    domains {id: {domain: is_root}})."""
    names: dict[int, str] = {}
    schedules: dict[int, str] = {}
    domains: dict[int, dict[str, bool]] = defaultdict(dict)

    try:
        fh = open(path, newline="", encoding="utf-8-sig")
    except OSError as exc:
        raise CsvError(f"cannot read {path}: {exc}") from exc

    with fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise CsvError("CSV has no header row")
        cols = [c.strip() for c in reader.fieldnames]
        missing = [c for c in REQUIRED_COLS if c not in cols]
        if missing:
            raise CsvError(
                f"CSV header missing {missing}; expected {list(REQUIRED_COLS)}"
            )

        for i, row in enumerate(reader, start=2):
            name = (row.get("Name") or "").strip()
            domain = (row.get("Domain") or "").strip().lower()
            raw_id = (row.get("ID") or "").strip()
            raw_root = row.get("Is Root?") or ""
            schedule = (row.get("Run Schedule") or "").strip()

            if not name:
                raise CsvError(f"line {i}: Name is empty")
            if not domain or "." not in domain or " " in domain:
                raise CsvError(f"line {i}: Domain is not a hostname: {domain!r}")
            try:
                cid = int(raw_id)
            except ValueError as exc:
                raise CsvError(f"line {i}: ID is not an integer: {raw_id!r}") from exc
            if cid <= 0:
                raise CsvError(f"line {i}: ID must be positive, got {cid}")
            is_root = parse_root(raw_root, i)
            if not schedule:
                raise CsvError(f"line {i}: Run Schedule is empty")

            if cid in names and names[cid] != name:
                raise CsvError(
                    f"line {i}: company {cid} name {name!r} conflicts with "
                    f"earlier {names[cid]!r}"
                )
            if cid in schedules and schedules[cid] != schedule:
                raise CsvError(
                    f"line {i}: company {cid} run schedule {schedule!r} "
                    f"conflicts with earlier {schedules[cid]!r}"
                )
            names[cid] = name
            schedules[cid] = schedule
            if domain in domains[cid]:
                domains[cid][domain] = domains[cid][domain] or is_root
            else:
                domains[cid][domain] = is_root

    if not names:
        raise CsvError("CSV contains no data rows")

    warnings = []
    for cid, dom_map in domains.items():
        roots = [d for d, root in dom_map.items() if root]
        if len(roots) != 1:
            warnings.append(
                f"company {cid} ({names[cid]!r}) has {len(roots)} root "
                f"domain(s): {', '.join(sorted(roots)) or '(none)'}"
            )
    for w in warnings:
        print(f"CSV warning: {w}", file=sys.stderr)

    return names, schedules, dict(domains)


def load_db(
    cur,
) -> tuple[dict[int, str], dict[int, str | None], dict[int, dict[str, bool]]]:
    cur.execute("SELECT id, name, run_schedule FROM public.companies")
    names: dict[int, str] = {}
    schedules: dict[int, str | None] = {}
    for cid, name, schedule in cur.fetchall():
        names[int(cid)] = name
        schedules[int(cid)] = schedule
    cur.execute("SELECT domain::text, company_id, is_root FROM public.domains")
    domains: dict[int, dict[str, bool]] = defaultdict(dict)
    for domain, cid, is_root in cur.fetchall():
        domains[int(cid)][domain.lower()] = bool(is_root)
    return names, schedules, dict(domains)


def plan(
    csv_names: dict[int, str],
    csv_schedules: dict[int, str],
    csv_doms: dict[int, dict[str, bool]],
    db_names: dict[int, str],
    db_schedules: dict[int, str | None],
    db_doms: dict[int, dict[str, bool]],
) -> dict:
    csv_ids = set(csv_names)
    db_ids = set(db_names)
    add_cos = sorted(csv_ids - db_ids)
    del_cos = sorted(db_ids - csv_ids)
    keep_ids = csv_ids & db_ids
    renamed = [i for i in keep_ids if csv_names[i] != db_names[i]]
    rescheduled = [
        i for i in keep_ids if (db_schedules.get(i) or "") != csv_schedules[i]
    ]

    add_doms: list[tuple[int, str, bool]] = []
    del_doms: list[tuple[int, str]] = []
    mod_root: list[tuple[int, str, bool]] = []
    reset_enum: set[int] = set(add_cos)

    for cid in csv_ids:
        incoming = csv_doms.get(cid, {})
        existing = db_doms.get(cid, {}) if cid in db_ids else {}
        for d, root in incoming.items():
            if d not in existing:
                add_doms.append((cid, d, root))
            elif existing[d] != root:
                mod_root.append((cid, d, root))
        for d in existing:
            if d not in incoming:
                del_doms.append((cid, d))
        if cid in db_ids:
            added = any(d not in existing for d in incoming)
            flipped = any(
                d in existing and existing[d] != incoming[d] for d in incoming
            )
            if added or flipped:
                reset_enum.add(cid)

    return {
        "add_cos": add_cos,
        "del_cos": del_cos,
        "renamed": renamed,
        "rescheduled": rescheduled,
        "add_doms": add_doms,
        "del_doms": del_doms,
        "mod_root": mod_root,
        "reset_enum": reset_enum,
        "csv_names": csv_names,
        "csv_schedules": csv_schedules,
        "csv_doms": csv_doms,
    }


def print_preview(p: dict) -> None:
    print("Planned sync (CSV is source of truth)")
    print(
        f"  companies  add={len(p['add_cos'])}  "
        f"rename={len(p['renamed'])}  "
        f"run_schedule change={len(p['rescheduled'])}  "
        f"delete={len(p['del_cos'])}  "
        f"last_enum reset={len(p['reset_enum'])}"
    )
    print(
        f"  domains    add={len(p['add_doms'])}  "
        f"is_root change={len(p['mod_root'])}  delete={len(p['del_doms'])}"
    )


def apply(cur, p: dict) -> None:
    if p["del_cos"]:
        cur.execute(
            "DELETE FROM public.companies WHERE id = ANY(%s)",
            (p["del_cos"],),
        )

    if p["add_cos"]:
        rows = [
            (i, p["csv_names"][i], p["csv_schedules"][i], None)
            for i in p["add_cos"]
        ]
        execute_values(
            cur,
            "INSERT INTO public.companies (id, name, run_schedule, last_enum) "
            "VALUES %s",
            rows,
        )

    for cid in p["renamed"]:
        cur.execute(
            "UPDATE public.companies SET name = %s WHERE id = %s",
            (p["csv_names"][cid], cid),
        )

    for cid in p["rescheduled"]:
        cur.execute(
            "UPDATE public.companies SET run_schedule = %s WHERE id = %s",
            (p["csv_schedules"][cid], cid),
        )

    if p["del_doms"]:
        cur.execute(
            "DELETE FROM public.domains WHERE (company_id, domain) IN "
            "(SELECT x, y FROM UNNEST(%s::int[], %s::citext[]) AS t(x, y))",
            (
                [c for c, _ in p["del_doms"]],
                [d for _, d in p["del_doms"]],
            ),
        )

    if p["add_doms"]:
        execute_values(
            cur,
            "INSERT INTO public.domains (domain, company_id, is_root) VALUES %s",
            [(d, cid, root) for cid, d, root in p["add_doms"]],
        )

    for cid, domain, root in p["mod_root"]:
        cur.execute(
            "UPDATE public.domains SET is_root = %s "
            "WHERE company_id = %s AND domain = %s",
            (root, cid, domain),
        )

    if p["reset_enum"]:
        cur.execute(
            "UPDATE public.companies SET last_enum = NULL WHERE id = ANY(%s)",
            (list(p["reset_enum"]),),
        )


def confirm() -> bool:
    try:
        ans = input("Proceed with these changes? [y/N]: ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync companies/domains from CSV")
    parser.add_argument(
        "filename",
        help="CSV with ID,Name,Domain,Is Root?,Run Schedule",
    )
    args = parser.parse_args()

    try:
        csv_names, csv_schedules, csv_doms = load_csv(args.filename)
    except CsvError as exc:
        print(f"CSV error: {exc}", file=sys.stderr)
        return 2

    try:
        conn = psycopg2.connect(**DB)
    except Exception as exc:
        print(f"Database connection failed: {exc}", file=sys.stderr)
        return 3

    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            db_names, db_schedules, db_doms = load_db(cur)
            p = plan(
                csv_names,
                csv_schedules,
                csv_doms,
                db_names,
                db_schedules,
                db_doms,
            )
            print_preview(p)
            if not confirm():
                print("Aborted. No changes written.")
                conn.rollback()
                return 0
            apply(cur, p)
            conn.commit()
        print("Sync complete.")
        print(
            f"  companies  added={len(p['add_cos'])}  "
            f"renamed={len(p['renamed'])}  "
            f"run_schedule changed={len(p['rescheduled'])}  "
            f"deleted={len(p['del_cos'])}  "
            f"last_enum reset={len(p['reset_enum'])}"
        )
        print(
            f"  domains    added={len(p['add_doms'])}  "
            f"is_root changed={len(p['mod_root'])}  deleted={len(p['del_doms'])}"
        )
        return 0
    except Exception as exc:
        conn.rollback()
        print(f"Sync failed, transaction rolled back: {exc}", file=sys.stderr)
        return 4
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
