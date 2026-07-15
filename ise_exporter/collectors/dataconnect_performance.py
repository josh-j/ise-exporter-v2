"""Latest PSN/node performance and bounded diagnostic aggregates."""
from .. import metrics
from . import observe
from .dataconnect_common import (
    hourly_rollup_window_hours,
    group_limit,
    integer,
    label,
    number,
    query_set,
    recent_event_predicate,
    replace_snapshot,
)


_METRICS = (
    metrics.ise_dataconnect_psn_radius_requests_per_hour,
    metrics.ise_dataconnect_psn_mnt_logs_per_hour,
    metrics.ise_dataconnect_psn_noise_per_hour,
    metrics.ise_dataconnect_psn_suppression_per_hour,
    metrics.ise_dataconnect_psn_load_percent,
    metrics.ise_dataconnect_psn_average_latency_seconds,
    metrics.ise_dataconnect_psn_average_tps,
    metrics.ise_dataconnect_node_cpu_utilization_percent,
    metrics.ise_dataconnect_node_memory_utilization_percent,
    metrics.ise_dataconnect_node_disk_utilization_percent,
    metrics.ise_dataconnect_diagnostic_events,
    metrics.ise_dataconnect_diagnostic_events_total,
    metrics.ise_dataconnect_diagnostic_topk_groups_returned,
    metrics.ise_dataconnect_diagnostic_topk_groups_total,
    metrics.ise_dataconnect_diagnostic_topk_truncated,
)


def _queries(limit, window_hours=6):
    kpi_recent = recent_event_predicate("logged_time", window_hours)
    timestamp_recent = recent_event_predicate("timestamp", window_hours)
    return {
        "kpi": f"""
            SELECT ise_node, radius_requests_hr, logged_to_mnt_hr, noise_hr,
                   suppression_hr, avg_load, max_load, avg_latency_per_req, avg_tps
            FROM (
                SELECT ise_node, radius_requests_hr, logged_to_mnt_hr, noise_hr,
                       suppression_hr, avg_load, max_load, avg_latency_per_req, avg_tps,
                       ROW_NUMBER() OVER
                    (PARTITION BY ise_node ORDER BY logged_time DESC) AS row_num
                FROM key_performance_metrics k
                WHERE {kpi_recent}
            ) WHERE row_num = 1
        """,
        "system": f"""
            SELECT ise_node, cpu_utilization, memory_utilization, diskspace_root,
                   diskspace_boot, diskspace_opt, diskspace_storedconfig,
                   diskspace_tmp, diskspace_runtime
            FROM (
                SELECT ise_node, cpu_utilization, memory_utilization, diskspace_root,
                       diskspace_boot, diskspace_opt, diskspace_storedconfig,
                       diskspace_tmp, diskspace_runtime, ROW_NUMBER() OVER
                    (PARTITION BY ise_node ORDER BY timestamp DESC) AS row_num
                FROM system_summary s
                WHERE {timestamp_recent}
            ) WHERE row_num = 1
        """,
        "aaa_diagnostics": f"""
            SELECT grouped_diagnostics.*,
                   SUM(events) OVER () AS total_events,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT ise_node, message_severity, category, message_code,
                       COUNT(*) AS events
                FROM aaa_diagnostics_view
                WHERE {timestamp_recent}
                GROUP BY ise_node, message_severity, category, message_code
            ) grouped_diagnostics
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "system_diagnostics": f"""
            SELECT grouped_diagnostics.*,
                   SUM(events) OVER () AS total_events,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT ise_node, message_severity, category, message_code,
                       COUNT(*) AS events
                FROM system_diagnostics_view
                WHERE {timestamp_recent}
                GROUP BY ise_node, message_severity, category, message_code
            ) grouped_diagnostics
            ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace latest node samples and diagnostic aggregates."""
    with observe("dataconnect_performance"):
        rows = query_set(
            dataconnect,
            _queries(
                group_limit(cfg), hourly_rollup_window_hours(
                    cfg, getattr(cfg, "dataconnect_performance_interval", 21600))),
        )
        kpis = [{
            "node": label(row.get("ise_node")),
            "requests": number(row.get("radius_requests_hr")),
            "logs": number(row.get("logged_to_mnt_hr")),
            "noise": number(row.get("noise_hr")),
            "suppression": number(row.get("suppression_hr")),
            "avg_load": number(row.get("avg_load")),
            "max_load": number(row.get("max_load")),
            "latency": number(row.get("avg_latency_per_req")) / 1000.0,
            "tps": number(row.get("avg_tps")),
        } for row in rows["kpi"]]
        systems = [{
            "node": label(row.get("ise_node")),
            "cpu": number(row.get("cpu_utilization")),
            "memory": number(row.get("memory_utilization")),
            "disks": {
                "/": number(row.get("diskspace_root")),
                "/boot": number(row.get("diskspace_boot")),
                "/opt": number(row.get("diskspace_opt")),
                "/storedconfig": number(row.get("diskspace_storedconfig")),
                "/tmp": number(row.get("diskspace_tmp")),
                "/runtime": number(row.get("diskspace_runtime")),
            },
        } for row in rows["system"]]
        diagnostics = []
        diagnostic_summaries = {}
        for source in ("aaa", "system"):
            source_rows = rows[f"{source}_diagnostics"]
            diagnostic_summaries[source] = source_rows[0] if source_rows else {}
            for row in source_rows:
                diagnostics.append({
                    "source": source,
                    "node": label(row.get("ise_node")),
                    "severity": label(row.get("message_severity")),
                    "category": label(row.get("category"), "none"),
                    "code": label(row.get("message_code")),
                    "events": integer(row.get("events")),
                })

        writers = []
        for row in kpis:
            writers.extend((
                lambda row=row: metrics.ise_dataconnect_psn_radius_requests_per_hour.labels(
                    node=row["node"]).set(row["requests"]),
                lambda row=row: metrics.ise_dataconnect_psn_mnt_logs_per_hour.labels(
                    node=row["node"]).set(row["logs"]),
                lambda row=row: metrics.ise_dataconnect_psn_noise_per_hour.labels(
                    node=row["node"]).set(row["noise"]),
                lambda row=row: metrics.ise_dataconnect_psn_suppression_per_hour.labels(
                    node=row["node"]).set(row["suppression"]),
                lambda row=row: metrics.ise_dataconnect_psn_load_percent.labels(
                    node=row["node"], stat="avg").set(row["avg_load"]),
                lambda row=row: metrics.ise_dataconnect_psn_load_percent.labels(
                    node=row["node"], stat="max").set(row["max_load"]),
                lambda row=row: metrics.ise_dataconnect_psn_average_latency_seconds.labels(
                    node=row["node"]).set(row["latency"]),
                lambda row=row: metrics.ise_dataconnect_psn_average_tps.labels(
                    node=row["node"]).set(row["tps"]),
            ))
        for row in systems:
            writers.extend((
                lambda row=row: metrics.ise_dataconnect_node_cpu_utilization_percent.labels(
                    node=row["node"]).set(row["cpu"]),
                lambda row=row: metrics.ise_dataconnect_node_memory_utilization_percent.labels(
                    node=row["node"]).set(row["memory"]),
            ))
            writers.extend(
                lambda row=row, partition=partition, value=value:
                metrics.ise_dataconnect_node_disk_utilization_percent.labels(
                    node=row["node"], partition=partition).set(value)
                for partition, value in row["disks"].items()
            )
        writers.extend(
            lambda row=row: metrics.ise_dataconnect_diagnostic_events.labels(
                source=row["source"], node=row["node"], severity=row["severity"],
                category=row["category"], message_code=row["code"]).set(row["events"])
            for row in diagnostics
        )
        for source, summary in diagnostic_summaries.items():
            returned = len(rows[f"{source}_diagnostics"])
            total_events = integer(summary.get("total_events"))
            total_groups = integer(summary.get("total_groups"))
            writers.extend((
                lambda source=source, total_events=total_events:
                    metrics.ise_dataconnect_diagnostic_events_total.labels(
                        source=source).set(total_events),
                lambda source=source, returned=returned:
                    metrics.ise_dataconnect_diagnostic_topk_groups_returned.labels(
                        source=source).set(returned),
                lambda source=source, total_groups=total_groups:
                    metrics.ise_dataconnect_diagnostic_topk_groups_total.labels(
                        source=source).set(total_groups),
                lambda source=source, returned=returned, total_groups=total_groups:
                    metrics.ise_dataconnect_diagnostic_topk_truncated.labels(
                        source=source).set(1 if returned < total_groups else 0),
            ))
        replace_snapshot(_METRICS, writers)
