#!/usr/bin/env python3
"""
Real-time terminal dashboard for the Amass engine's backlog API.

Run with sudo, since it shells out to `docker exec`, which itself
requires sudo on this machine - running the whole script as root avoids
being prompted for a password every 2-second cycle:

    sudo python3 dashboard.py

Assumes exactly one session is ever running at a time, per the actual
deployment model (each engine only ever runs one session). If somehow
more than one session exists, this just uses the first one returned.
"""

import json
import math
import os
import subprocess
import sys
import time
from collections import deque
from datetime import datetime

CONTAINER = "engine"
POLL_SECONDS = 2
API_BASE = "http://localhost:4000/api/v1"
LINE_WIDTH = 100
# The rate column is a running average over this many seconds of samples.
AVG_WINDOW_SECONDS = 15
# Host WAN/VLAN iface (Internet only). Not docker0 / not engine eth0.
WAN_IFACE = os.environ.get("WAN_IFACE", "ens33")

# Session-end ("end-work") limits, copied from the engine
# (protocol_probes/sweep.go, support/owned_netblock.go). The engine does not
# report them; update these if the engine's values change.
SWEEP_MAX_RESUBMIT = 500          # the requeue step stops after this many IPs
SWEEP_IDLE_WAIT_S = 2 * 60        # idle-wait gives up after this long
SWEEP_DRAIN_WAIT_S = 15 * 60      # drain gives up after this long
OWNED_FILL_WAIT_S = 3 * 60 * 60   # owned-fill waits this long for the IP backlog


def docker_exec_get(path):
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "wget", "-qO-", API_BASE + path],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("docker exec timed out")

    if result.returncode != 0:
        raise RuntimeError(f"request failed: {result.stderr.strip() or 'no response'}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"unexpected response: {result.stdout[:200]!r}")


def get_session_token():
    data = docker_exec_get("/sessions/list")
    tokens = data.get("sessionTokens") or []
    if not tokens:
        raise RuntimeError("no active session found")
    return tokens[0]


def get_end_work(token):
    try:
        return docker_exec_get(f"/sessions/{token}/end-work")
    except RuntimeError:
        return None


def read_iface_bytes(iface):
    """Host sysfs counters. Returns (rx, tx) or (None, None)."""
    try:
        with open(f"/sys/class/net/{iface}/statistics/rx_bytes") as f:
            rx = int(f.read().strip())
        with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f:
            tx = int(f.read().strip())
        return rx, tx
    except (OSError, ValueError):
        return None, None


def fmt_mib(n):
    return "n/a" if n is None else f"{n / 1048576:.1f} MiB"



def clear_screen():
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()


def lr(left, right, width=LINE_WIDTH):
    pad = max(1, width - len(left) - len(right))
    return left + " " * pad + right


def rate_between(old, cur, span):
    """Per-second rate between two samples span seconds apart, or None if unknown."""
    if old is None or cur is None or not span or span <= 0:
        return None
    return (cur - old) / span


def fmt_rate(rate):
    """The rate column: '+12.3', or blank when there is no rate yet."""
    return "" if rate is None else f"{rate:+.1f}"


def fmt_etc(remaining, rate):
    """Estimated time to complete: remaining items at the current rate, as
    '00h 00m' (minutes rounded down; hours grow past 99 as needed).

    '--' when there is no rate, or the rate as displayed is +0.0 or below.
    """
    if rate is None or round(rate, 1) <= 0:
        return "--"
    minutes = int(max(0, remaining) / rate // 60)
    return f"{minutes // 60:02d}h {minutes % 60:02d}m"


def window_rate(history, now, cur, value_of):
    """Running average rate over the last AVG_WINDOW_SECONDS.

    history holds earlier samples, oldest first; value_of(sample) extracts the
    counter from one (None if that sample lacks it). The rate is measured from
    the oldest sample still inside the window that has the counter, so it is
    the average over (up to) the last AVG_WINDOW_SECONDS rather than over the
    last poll only. Returns the rate per second, or None if there is no
    earlier sample to measure from yet.
    """
    for sample in history:
        t = sample[0]
        if now - t > AVG_WINDOW_SECONDS:
            continue
        old = value_of(sample)
        if old is not None:
            return rate_between(old, cur, now - t)
    return None


def fmt_dur(seconds):
    """'45s', '12m 05s', '3h 07m'."""
    s = int(max(0, seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {s % 3600 // 60:02d}m"


def ew_phase(end_work):
    """The end-work phase name, 'DONE' once the engine reports it finished."""
    if not end_work:
        return "n/a"
    if end_work.get("done"):
        return "DONE"
    return end_work.get("phase") or "none"


class EndWorkTracker:
    """Remembers when the dashboard first saw each end-work phase.

    The engine reports only the current phase and its counters, not when the
    phase started. The dashboard notes the time it first sees a phase, and the
    requeued count at that moment, so it can show how long the phase has run
    and its average rate over the whole phase. If the dashboard was started
    while a phase was already running, that phase's start is unknown: its
    elapsed time is shown with a leading '>' (at least this long), and its
    rate is measured from when the dashboard joined.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.phase = None
        self.phase_seen = None        # monotonic time the phase was first seen
        self.phase_joined = False     # True: the phase was already running
        self.req_at_seen = 0          # requeued count when the phase was first seen
        self.start_seen = None        # monotonic time end-work was first seen running
        self.start_joined = False
        self.finished_after = None    # end-work duration, once DONE

    def update(self, end_work, now):
        phase = ew_phase(end_work)
        req = int((end_work or {}).get("requeued") or 0)
        first_poll = self.phase is None
        if phase != self.phase:
            self.phase = phase
            self.phase_seen = now
            self.phase_joined = first_poll
            self.req_at_seen = req
            running = phase not in ("none", "n/a", "DONE")
            if running and self.start_seen is None:
                self.start_seen = now
                self.start_joined = first_poll
            if phase == "DONE" and self.start_seen is not None and self.finished_after is None:
                self.finished_after = now - self.start_seen

    def phase_elapsed(self, now):
        if self.phase_seen is None:
            return ""
        return (">" if self.phase_joined else "") + fmt_dur(now - self.phase_seen)

    def phase_rate(self, end_work, now):
        """Requeued IPs per second over the phase so far, or None."""
        if self.phase_seen is None or now - self.phase_seen < POLL_SECONDS:
            return None
        req = int((end_work or {}).get("requeued") or 0)
        return (req - self.req_at_seen) / (now - self.phase_seen)

    def time_left(self, limit_s, now):
        """Seconds until a phase's engine time limit, or None if the start is unknown."""
        if self.phase_seen is None or self.phase_joined:
            return None
        return limit_s - (now - self.phase_seen)


def print_table_header(title):
    print("-" * LINE_WIDTH)
    print(f"{title:<22} {'waiting':>9} {'leased':>9} {'queue':>8} "
          f"{'processed':>12} {'avg/s 15s':>10} {'ETC':>9}")
    print("-" * LINE_WIDTH)


def print_row(name, waiting, leased, queue, processed, rate, etc):
    print(f"{name:<22} {waiting:>9} {leased:>9} {queue:>8} "
          f"{processed:>12} {rate:>10} {etc:>9}")


def fmt_rate_min(rate_per_s):
    """A per-minute rate for the end-work row: '12.5', or blank when unknown."""
    return "" if rate_per_s is None else f"{rate_per_s * 60:.1f}"


def render_end_work(end_work, tracker, ip_rate, now):
    """The end-work section: one row whose columns fit the current phase,
    plus a line or two saying what the phase is doing and how it ends.

    Columns: elapsed (time in this phase), requeued (IPs sent back to
    Protocol-Probes), of (the most the phase can requeue), progress,
    rate/min (over the whole phase) and ETC.
    """
    print("-" * LINE_WIDTH)
    print(f"{'end-work':<22} {'elapsed':>9} {'requeued':>9} {'of':>8} "
          f"{'progress':>12} {'rate/min':>10} {'ETC':>9}")
    print("-" * LINE_WIDTH)

    phase = tracker.phase or ew_phase(end_work)
    ew = end_work or {}
    cand = int(ew.get("candidates") or 0)
    req = int(ew.get("requeued") or 0)
    ip_left = int(ew.get("waiting") or 0) + int(ew.get("leased") or 0)
    # Elapsed time means nothing before end-work starts.
    elapsed = "" if phase in ("none", "n/a", "DONE") else tracker.phase_elapsed(now)
    notes = []

    def row(name, requeued="", of="", progress="", rate="", etc="--"):
        print(f"{name:<22} {elapsed:>9} {requeued:>9} {of:>8} "
              f"{progress:>12} {rate:>10} {etc:>9}")

    def limit_note(what, limit_s):
        left = tracker.time_left(limit_s, now)
        if left is None:
            return f"{what} gives up after {fmt_dur(limit_s)} (start not seen)."
        return f"{what} gives up after {fmt_dur(limit_s)} ({fmt_dur(left)} left)."

    if not end_work:
        row("n/a")
        notes.append("End-work status unavailable.")
    elif phase == "none":
        row("not started")
    elif phase == "owned-fill":
        rate = ip_rate
        row("owned-fill", progress=f"{ip_left:,} IP left",
            rate=fmt_rate_min(rate), etc=fmt_etc(ip_left, rate))
        notes.append("Filling owned netblocks; the IP backlog grows while blocks are being filled.")
        notes.append(f"Then the engine waits up to {fmt_dur(OWNED_FILL_WAIT_S)} for the IP backlog "
                     f"to drain before the sweep starts.")
    elif phase == "idle-wait":
        row("idle-wait", progress=f"{ip_left:,} IP busy")
        notes.append(limit_note("Waiting for the IP pipeline to go idle;", SWEEP_IDLE_WAIT_S))
    elif phase == "listing":
        row("listing")
        notes.append("Listing finished IPs and finding the ones Protocol-Probes missed.")
    elif phase == "requeue":
        rate = tracker.phase_rate(end_work, now)
        if cand > SWEEP_MAX_RESUBMIT:
            # Fallback: the engine checks every finished IP one at a time and
            # stops after SWEEP_MAX_RESUBMIT requeues or at the end of the list.
            # It does not report its position in the list, so progress is
            # measured against the cap: a ceiling, not a true percentage.
            pct = min(100.0, req / SWEEP_MAX_RESUBMIT * 100)
            row("requeue (walk)", f"{req:,}", f"{SWEEP_MAX_RESUBMIT:,}", f"{pct:.1f}%",
                fmt_rate_min(rate), fmt_etc(SWEEP_MAX_RESUBMIT - req, rate))
        else:
            # Batched: candidates is the exact list of IPs to requeue.
            total = cand
            pct = (req / total * 100) if total else 100.0
            row("requeue (batch)", f"{req:,}", f"{total:,}", f"{pct:.1f}%",
                fmt_rate_min(rate), fmt_etc(total - req, rate))
    elif phase == "drain":
        rate = ip_rate
        row("drain", f"{req:,}", "", f"{ip_left:,} IP left",
            fmt_rate_min(rate), fmt_etc(ip_left, rate))
        notes.append(f"Protocol-Probes is re-running on the {req:,} requeued IPs.")
        notes.append(limit_note("The engine", SWEEP_DRAIN_WAIT_S))
    elif phase == "DONE":
        # elapsed: how long end-work took in total, when the dashboard saw it start.
        elapsed = ""
        if tracker.finished_after is not None:
            elapsed = (">" if tracker.start_joined else "") + fmt_dur(tracker.finished_after)
        row("DONE", f"{req:,}")
        if elapsed:
            notes.append(f"End-work finished in {elapsed}.")
    else:
        row(phase, f"{req:,}")

    for n in notes:
        print(n[:LINE_WIDTH])


def render(token, buckets, bucket_rates, elapsed,
           netsem_in, netsem_cap, scansem_in, scansem_cap,
           prefilter_scanned, prefilter_open, end_work, ew_tracker,
           wan_line):
    clear_screen()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(lr(f"Session: {token}", f"TIME: {now}"))

    netsem_cap = netsem_cap or 500
    scansem_cap = scansem_cap or 3200
    gauges = f"NetSem: {netsem_in}/{netsem_cap}  ScanSem: {scansem_in}/{scansem_cap}"
    print(lr(f"Elapsed: {elapsed}", gauges))

    skipped = prefilter_scanned - prefilter_open
    if prefilter_scanned > 0:
        pct = math.floor((skipped / prefilter_scanned * 100) * 10) / 10
        pre = f"Pre-filter: {skipped:,}/{prefilter_scanned:,} ports skipped ({pct:.1f}%)"
    else:
        pre = "Pre-filter: (no data yet)"
    print(lr(pre, wan_line))

    print_table_header("bucket")
    if not buckets:
        print("(no buckets with any activity yet)")
    else:
        for b in sorted(buckets, key=lambda x: x["asset_type"]):
            atype = b["asset_type"]
            processed = b["processed"]
            rate = bucket_rates.get(atype)
            # Remaining work is waiting + leased; queue is already inside leased.
            print_row(atype, b["waiting"], b["leased"], b["queue"], processed,
                      fmt_rate(rate), fmt_etc(b["waiting"] + b["leased"], rate))

    render_end_work(end_work, ew_tracker, bucket_rates.get("IPAddress"), time.monotonic())

    print("-" * LINE_WIDTH)
    print("Ctrl+C to stop")


def render_waiting(message):
    clear_screen()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(lr("amass engine backlog  |  waiting for engine...", f"TIME: {now}"))
    print(f"  ({message})")
    print("Ctrl+C to stop")


def main():
    # Recent samples, oldest first: (monotonic time, {asset_type: processed}).
    # Only the last AVG_WINDOW_SECONDS are kept.
    history = deque()
    ew_tracker = EndWorkTracker()
    current_token = None
    session_start = None
    wan_rx0 = wan_tx0 = None

    try:
        while True:
            try:
                token = get_session_token()
                if token != current_token:
                    current_token = token
                    session_start = time.time()
                    history.clear()
                    ew_tracker.reset()
                    wan_rx0, wan_tx0 = read_iface_bytes(WAN_IFACE)

                data = docker_exec_get(f"/sessions/{token}/backlog")
                end_work = get_end_work(token)
                buckets = data.get("buckets") or []
                elapsed_s = int(time.time() - session_start)
                elapsed = f"{elapsed_s // 60}m {elapsed_s % 60}s"

                sample_time = time.monotonic()
                while history and sample_time - history[0][0] > AVG_WINDOW_SECONDS:
                    history.popleft()
                bucket_rates = {
                    b["asset_type"]: window_rate(
                        history, sample_time, b["processed"],
                        lambda s, a=b["asset_type"]: s[1].get(a))
                    for b in buckets
                }
                ew_tracker.update(end_work, sample_time)

                wan_rx, wan_tx = read_iface_bytes(WAN_IFACE)
                if wan_rx0 is None or wan_rx is None:
                    wan_line = f"{WAN_IFACE}: n/a"
                else:
                    wan_line = (
                        f"{WAN_IFACE}  rx {fmt_mib(wan_rx - wan_rx0)}  "
                        f"tx {fmt_mib(wan_tx - wan_tx0)}"
                    )

                render(
                    token, buckets, bucket_rates, elapsed,
                    data.get("active_connections", 0),
                    data.get("max_connections", 0),
                    data.get("active_scan_conns", 0),
                    data.get("max_scan_conns", 0),
                    data.get("prefilter_scanned", 0),
                    data.get("prefilter_open", 0),
                    end_work,
                    ew_tracker,
                    wan_line,
                )

                history.append((
                    sample_time,
                    {b["asset_type"]: b["processed"] for b in buckets},
                ))

            except RuntimeError as e:
                render_waiting(str(e))
                history.clear()

            time.sleep(POLL_SECONDS)

    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
