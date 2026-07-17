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
    schema_columns,
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


_KPI_VALUES = (
    "radius_requests_hr", "logged_to_mnt_hr", "noise_hr", "suppression_hr",
    "avg_load", "max_load", "avg_latency_per_req", "avg_tps",
)
_SYSTEM_VALUES = (
    "cpu_utilization", "memory_utilization", "diskspace_root", "diskspace_boot",
    "diskspace_opt", "diskspace_storedconfig", "diskspace_tmp", "diskspace_runtime",
)
_DIAGNOSTIC_DIMENSIONS = ("message_severity", "category", "message_code")


def _selected_columns(schema, view, required, optional):
    available = schema_columns(schema, view)
    return tuple(required) + tuple(
        column for column in optional
        if available is None or column.upper() in available
    )


def _latest_query(view, time_column, columns, recent):
    selected = ", ".join(columns)
    return f"""
        SELECT {selected}
        FROM (
            SELECT {selected}, ROW_NUMBER() OVER
                (PARTITION BY ise_node ORDER BY {time_column} DESC) AS row_num
            FROM {view}
            WHERE {recent}
        ) WHERE row_num = 1
    """


def _diagnostic_query(view, columns, recent, limit):
    available = set(columns)
    selected = ["ise_node"]
    grouped = ["ise_node"]
    for column in _DIAGNOSTIC_DIMENSIONS:
        if column in available:
            selected.append(column)
            grouped.append(column)
        else:
            selected.append(f"'unknown' AS {column}")
    return f"""
        SELECT grouped_diagnostics.*,
               SUM(events) OVER () AS total_events,
               COUNT(*) OVER () AS total_groups
        FROM (
            SELECT {", ".join(selected)}, COUNT(*) AS events
            FROM {view}
            WHERE {recent}
            GROUP BY {", ".join(grouped)}
        ) grouped_diagnostics
        ORDER BY events DESC FETCH FIRST {limit} ROWS ONLY
    """


def _queries(limit, window_hours=6, schema=None):
    kpi_recent = recent_event_predicate("logged_time", window_hours)
    timestamp_recent = recent_event_predicate("timestamp", window_hours)
    kpi_columns = _selected_columns(
        schema, "KEY_PERFORMANCE_METRICS", ("ise_node",), _KPI_VALUES)
    system_columns = _selected_columns(
        schema, "SYSTEM_SUMMARY", ("ise_node",), _SYSTEM_VALUES)
    aaa_columns = _selected_columns(
        schema, "AAA_DIAGNOSTICS_VIEW", ("ise_node",), _DIAGNOSTIC_DIMENSIONS)
    system_diagnostic_columns = _selected_columns(
        schema, "SYSTEM_DIAGNOSTICS_VIEW", ("ise_node",), _DIAGNOSTIC_DIMENSIONS)
    return {
        "kpi": _latest_query(
            "key_performance_metrics", "logged_time", kpi_columns, kpi_recent),
        "system": _latest_query(
            "system_summary", "timestamp", system_columns, timestamp_recent),
        "aaa_diagnostics": _diagnostic_query(
            "aaa_diagnostics_view", aaa_columns, timestamp_recent, limit),
        "system_diagnostics": _diagnostic_query(
            "system_diagnostics_view", system_diagnostic_columns,
            timestamp_recent, limit),
    }


def collect(dataconnect, cfg):
    """Atomically replace latest node samples and diagnostic aggregates."""
    with observe("dataconnect_performance"):
        rows = query_set(
            dataconnect,
            _queries(
                group_limit(cfg), hourly_rollup_window_hours(
                    cfg, getattr(cfg, "dataconnect_performance_interval", 21600)),
                getattr(dataconnect, "schema", None)),
        )
        schema = getattr(dataconnect, "schema", None)
        kpi_available = schema_columns(schema, "KEY_PERFORMANCE_METRICS")
        system_available = schema_columns(schema, "SYSTEM_SUMMARY")
        kpis = [{
            "node": label(row.get("ise_node")),
            **{column: number(row[column]) for column in _KPI_VALUES
               if column in row and (kpi_available is None
                                     or column.upper() in kpi_available)},
        } for row in rows["kpi"]]
        systems = [{
            "node": label(row.get("ise_node")),
            **{column: number(row[column]) for column in _SYSTEM_VALUES
               if column in row and (system_available is None
                                     or column.upper() in system_available)},
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
            metric_values = (
                ("radius_requests_hr", metrics.ise_dataconnect_psn_radius_requests_per_hour),
                ("logged_to_mnt_hr", metrics.ise_dataconnect_psn_mnt_logs_per_hour),
                ("noise_hr", metrics.ise_dataconnect_psn_noise_per_hour),
                ("suppression_hr", metrics.ise_dataconnect_psn_suppression_per_hour),
                ("avg_latency_per_req", metrics.ise_dataconnect_psn_average_latency_seconds),
                ("avg_tps", metrics.ise_dataconnect_psn_average_tps),
            )
            for column, metric in metric_values:
                if column not in row:
                    continue
                value = row[column] / 1000.0 if column == "avg_latency_per_req" else row[column]
                writers.append(
                    lambda row=row, metric=metric, value=value:
                    metric.labels(node=row["node"]).set(value))
            for column, stat in (("avg_load", "avg"), ("max_load", "max")):
                if column in row:
                    writers.append(
                        lambda row=row, stat=stat, value=row[column]:
                        metrics.ise_dataconnect_psn_load_percent.labels(
                            node=row["node"], stat=stat).set(value))
        for row in systems:
            if "cpu_utilization" in row:
                writers.append(
                    lambda row=row: metrics.ise_dataconnect_node_cpu_utilization_percent.labels(
                        node=row["node"]).set(row["cpu_utilization"]))
            if "memory_utilization" in row:
                writers.append(
                    lambda row=row: metrics.ise_dataconnect_node_memory_utilization_percent.labels(
                        node=row["node"]).set(row["memory_utilization"]))
            partitions = {
                "diskspace_root": "/", "diskspace_boot": "/boot",
                "diskspace_opt": "/opt", "diskspace_storedconfig": "/storedconfig",
                "diskspace_tmp": "/tmp", "diskspace_runtime": "/runtime",
            }
            for column, partition in partitions.items():
                if column in row:
                    writers.append(
                        lambda row=row, partition=partition, value=row[column]:
                        metrics.ise_dataconnect_node_disk_utilization_percent.labels(
                            node=row["node"], partition=partition).set(value))
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
