#!/usr/bin/env python3
"""Read-only probe: is RADIUS_ACCOUNTING.ID a single global sequence or per-PSN?

This is the Slice 0 / Appendix-A gate for the incremental accounting-event
counters (dataconnect.accounting_event_counters). It decides whether the tail
cursor can be a single global cursor (the current Slice 1 design) or must become
per-(view, ise_node). It is READ-ONLY: three bounded SELECTs, no writes, parallel
query disabled, short timeout. Safe to run against production or a lab cluster.

Run it where Data Connect (:2484) is reachable, in the exporter's nix dev shell so
oracledb is available:

    ISE_DATACONNECT_HOST=laba-ise-001.ise.lab \
    ISE_DATACONNECT_PASSWORD='<dataconnect pw from sops>' \
    ISE_DATACONNECT_VERIFY=false \
    nix develop --command python tools/dataconnect_id_probe.py

Env vars (defaults in brackets):
    ISE_DATACONNECT_HOST       (required) MnT/PAN node exposing Data Connect
    ISE_DATACONNECT_PASSWORD   (required) the 'dataconnect' account password
    ISE_DATACONNECT_PORT       [2484]
    ISE_DATACONNECT_SERVICE    [cpm10]
    ISE_DATACONNECT_USER       [dataconnect]
    ISE_DATACONNECT_CA_BUNDLE  []  PEM path; only used when VERIFY=true
    ISE_DATACONNECT_VERIFY     [false]  true to verify the server cert + DN
    PROBE_WINDOW_HOURS         []  fixed lookback; default is adaptive (1,6,24,168)

The decisive output is A2: if the per-node [min_id, max_id] ranges INTERLEAVE, the
id is one global MnT-assigned sequence and Slice 1 is correct. If they are DISJOINT,
ids are per-PSN and the cursor must key on (view, ise_node). One node only =
inconclusive: bring up a second session-handling PSN and re-run.
"""
import os
import ssl
import sys
from datetime import datetime

try:
    import oracledb
except ImportError:
    sys.exit("oracledb not importable; run inside the exporter nix dev shell "
             "(nix develop --command python tools/dataconnect_id_probe.py)")


_ADAPTIVE_WINDOWS = (1, 6, 24, 168)  # hours: widen until the view has rows


def _connect():
    host = os.environ.get("ISE_DATACONNECT_HOST", "").strip()
    password = os.environ.get("ISE_DATACONNECT_PASSWORD", "")
    if not host or not password:
        sys.exit("set ISE_DATACONNECT_HOST and ISE_DATACONNECT_PASSWORD")
    port = int(os.environ.get("ISE_DATACONNECT_PORT", "2484"))
    service = os.environ.get("ISE_DATACONNECT_SERVICE", "cpm10")
    user = os.environ.get("ISE_DATACONNECT_USER", "dataconnect")
    ca_bundle = os.environ.get("ISE_DATACONNECT_CA_BUNDLE", "").strip()
    verify = os.environ.get("ISE_DATACONNECT_VERIFY", "false").strip().lower() in (
        "1", "true", "yes", "on")
    if verify:
        context = ssl.create_default_context(cafile=ca_bundle or None)
    else:
        context = ssl._create_unverified_context()
    print(f"connecting: {user}@{host}:{port}/{service} tcps verify={verify}",
          file=sys.stderr)
    connection = oracledb.connect(
        user=user, password=password, host=host, port=port,
        service_name=service, protocol="tcps", ssl_context=context,
        ssl_server_dn_match=verify, tcp_connect_timeout=30)
    connection.call_timeout = 30_000
    with connection.cursor() as cursor:
        # Monitoring, never a batch workload -- match the exporter's guard.
        cursor.execute("ALTER SESSION DISABLE PARALLEL QUERY", {})
    return connection


def _rows(connection, sql, hours):
    with connection.cursor() as cursor:
        cursor.execute(sql, {"hours": hours})
        columns = [c[0].lower() for c in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


_A1 = """
SELECT MIN(id) AS min_id, MAX(id) AS max_id, COUNT(*) AS n
FROM radius_accounting
WHERE timestamp >= CAST(SYSTIMESTAMP - NUMTODSINTERVAL(:hours, 'HOUR') AS TIMESTAMP)
"""

_A2 = """
SELECT ise_node, MIN(id) AS min_id, MAX(id) AS max_id, COUNT(*) AS n
FROM radius_accounting
WHERE timestamp >= CAST(SYSTIMESTAMP - NUMTODSINTERVAL(:hours, 'HOUR') AS TIMESTAMP)
GROUP BY ise_node
ORDER BY min_id
"""

_A3 = """
SELECT id, timestamp, event_timestamp, ise_node
FROM radius_accounting
WHERE timestamp >= CAST(SYSTIMESTAMP - NUMTODSINTERVAL(:hours, 'HOUR') AS TIMESTAMP)
ORDER BY id DESC
FETCH FIRST 100 ROWS ONLY
"""


def _find_window(connection):
    """Return (hours, a1_row) for the narrowest window that has accounting rows."""
    fixed = os.environ.get("PROBE_WINDOW_HOURS", "").strip()
    windows = (int(fixed),) if fixed else _ADAPTIVE_WINDOWS
    last = None
    for hours in windows:
        row = _rows(connection, _A1, hours)[0]
        last = (hours, row)
        if row.get("n"):
            return last
    return last


def _interpret_a2(rows):
    nodes = [(r["ise_node"], int(r["min_id"]), int(r["max_id"]), int(r["n"]))
             for r in rows if r.get("min_id") is not None]
    if not nodes:
        return "INCONCLUSIVE", "no accounting rows in the window."
    if len(nodes) == 1:
        return "INCONCLUSIVE", (
            f"only one ise_node wrote accounting ({nodes[0][0]}). A single writer "
            "cannot distinguish global from per-PSN. Enable the PSN persona on a "
            "second node, drive sessions to both, then re-run.")
    overlaps_all = True
    disjoint_all = True
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            _, a_min, a_max, _ = nodes[i]
            _, b_min, b_max, _ = nodes[j]
            if a_min <= b_max and b_min <= a_max:
                disjoint_all = False
            else:
                overlaps_all = False
    if overlaps_all:
        return "GLOBAL", (
            f"id ranges interleave across all {len(nodes)} nodes -> one MnT-assigned "
            "sequence. Slice 1's single (view, scope='') cursor is correct. PROCEED "
            "to enabling dataconnect.accounting_event_counters.")
    if disjoint_all:
        return "PER-PSN", (
            "each node's id range is disjoint -> per-PSN sequences. Switch the tail "
            "cursor to per-(view, ise_node) rows (the schema already keys on "
            "(view, scope)) BEFORE enabling Slice 1.")
    return "MIXED", (
        "some node ranges overlap and some are disjoint. Inspect A2 by hand; likely "
        "global with clustering, but confirm before enabling.")


def _interpret_a3(rows):
    """Largest add-time inversion vs id order -> a floor for tail_settle_seconds."""
    ordered = sorted(
        (r for r in rows if isinstance(r.get("timestamp"), datetime)),
        key=lambda r: int(r["id"]))
    worst = 0.0
    for earlier, later in zip(ordered, ordered[1:]):
        # later has the higher id; if its add-time is BEFORE the lower id's, that is
        # out-of-commit-order visibility -- the hazard the settle window guards.
        gap = (earlier["timestamp"] - later["timestamp"]).total_seconds()
        worst = max(worst, gap)
    if not ordered:
        return "no timestamped rows to assess."
    if worst <= 0:
        return "id order tracks add-time with no inversion in the sample (settle 30s is ample)."
    return (f"observed add-time inversion up to {worst:.0f}s (a higher id added "
            f"{worst:.0f}s before a lower id). Set tail_settle_seconds comfortably "
            f"above {worst:.0f}s.")


def _print_table(title, rows):
    print(f"\n=== {title} ===")
    if not rows:
        print("(no rows)")
        return
    columns = list(rows[0].keys())
    widths = {c: max(len(c), *(len(str(r.get(c))) for r in rows)) for c in columns}
    print("  ".join(c.ljust(widths[c]) for c in columns))
    for r in rows:
        print("  ".join(str(r.get(c)).ljust(widths[c]) for c in columns))


def main():
    connection = _connect()
    try:
        hours, a1 = _find_window(connection)
        print(f"\nlookback window: {hours}h  "
              f"(min_id={a1.get('min_id')} max_id={a1.get('max_id')} rows={a1.get('n')})")
        if not a1.get("n"):
            print("\nVERDICT: INCONCLUSIVE -- no accounting in the last "
                  f"{hours}h. Generate sessions (adws auth fleet) and re-run.")
            return 2

        a2 = _rows(connection, _A2, hours)
        a3 = _rows(connection, _A3, hours)
        _print_table("A2  per-node id ranges (decisive)", a2)
        verdict, why = _interpret_a2(a2)
        _print_table("A3  newest 100 rows by id (add-time vs id)", a3[:15])
        print(f"\nA3 settle sizing: {_interpret_a3(a3)}")
        print(f"\n{'=' * 70}\nVERDICT: {verdict}\n  {why}\n{'=' * 70}")
        return 0 if verdict in ("GLOBAL", "PER-PSN") else 3
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
