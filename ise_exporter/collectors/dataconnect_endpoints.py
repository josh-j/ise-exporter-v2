"""Endpoint inventory and profiling reporting from Cisco ISE Data Connect."""
from .. import metrics
from . import observe
from .dataconnect_common import (
    event_window_hours,
    group_limit,
    integer,
    label,
    query_set,
    recent_event_predicate,
    replace_snapshot,
    schema_expression,
    schema_has,
)


_METRICS = (
    metrics.ise_dataconnect_endpoints_total,
    metrics.ise_dataconnect_endpoints_unknown_profile_total,
    metrics.ise_dataconnect_endpoint_field_populated,
    metrics.ise_dataconnect_endpoint_field_coverage_ratio,
    metrics.ise_dataconnect_endpoints_stale,
    metrics.ise_dataconnect_profiled_endpoint_group_memberships_total,
    metrics.ise_dataconnect_endpoints_by_profile,
    metrics.ise_dataconnect_endpoints_by_identity_group,
    metrics.ise_dataconnect_endpoints_by_posture_applicable,
    metrics.ise_dataconnect_profile_events,
    metrics.ise_dataconnect_endpoint_topk_groups_returned,
    metrics.ise_dataconnect_endpoint_topk_groups_total,
    metrics.ise_dataconnect_endpoint_topk_truncated,
)


def _queries(limit, window_hours=6, schema=None):
    profiling_recent = recent_event_predicate("timestamp", window_hours)
    inventory_view = "ENDPOINTS_DATA"
    profile = schema_expression(schema, inventory_view, "endpoint_policy", "'Unknown'")
    identity_group = schema_expression(
        schema, inventory_view, "identity_group_id", "'none'")

    def populated(column, alias):
        if not schema_has(schema, inventory_view, column):
            return f"NULL AS {alias}"
        return f"SUM(CASE WHEN TRIM({column}) IS NOT NULL THEN 1 ELSE 0 END) AS {alias}"

    posture = ("SUM(CASE WHEN NVL(posture_applicable, 0) = 1 THEN 1 ELSE 0 END) "
               "AS posture_yes, "
               "SUM(CASE WHEN NVL(posture_applicable, 0) = 1 THEN 0 ELSE 1 END) "
               "AS posture_no") if schema_has(schema, inventory_view, "posture_applicable") \
        else "NULL AS posture_yes, NULL AS posture_no"
    unknown_profile = f"""SUM(CASE WHEN TRIM({profile}) IS NULL
                                  OR LOWER(TRIM({profile})) IN
                                      ('unknown', 'none', 'missing')
                            THEN 1 ELSE 0 END) AS unknown_profile""" \
        if schema_has(schema, inventory_view, "endpoint_policy") \
        else "NULL AS unknown_profile"

    def stale(days):
        if not schema_has(schema, inventory_view, "update_time"):
            return f"NULL AS stale_{days}"
        return f"""SUM(CASE WHEN update_time < SYSTIMESTAMP -
                                  NUMTODSINTERVAL({days}, 'DAY')
                              OR update_time IS NULL THEN 1 ELSE 0 END) AS stale_{days}"""

    profiling_view = "PROFILED_ENDPOINTS_SUMMARY"
    profiling_dimensions = {
        column: schema_expression(schema, profiling_view, column, fallback)
        for column, fallback in (
            ("endpoint_profile", "'Unknown'"), ("source", "'Unknown'"),
            ("endpoint_action_name", "'none'"), ("identity_group", "'none'"),
        )
    }
    return {
        "inventory": f"""
            WITH inventory_source AS (
                SELECT endpoints_data.*,
                       {profile} AS metric_profile,
                       {identity_group} AS metric_identity_group
                FROM endpoints_data
            ), inventory_groups AS (
                SELECT CASE
                           WHEN GROUPING(metric_profile) = 1
                            AND GROUPING(metric_identity_group) = 1 THEN 'coverage'
                           WHEN GROUPING(metric_profile) = 0 THEN 'profile'
                           ELSE 'identity_group'
                       END AS dimension,
                       CASE WHEN GROUPING(metric_profile) = 0
                            THEN metric_profile ELSE metric_identity_group END AS dimension_value,
                       COUNT(*) AS endpoints,
                       {populated("hostname", "hostname")},
                       {populated("endpoint_ip", "ip")},
                       {populated("custom_attributes", "custom_attributes")},
                       {populated("portal_user", "portal_user")},
                       {populated("mdm_guid", "mdm")},
                       {populated("native_udid", "udid")},
                       {posture},
                       {unknown_profile},
                       {stale(30)}, {stale(90)}, {stale(180)}
                FROM inventory_source
                GROUP BY GROUPING SETS ((), (metric_profile), (metric_identity_group))
            ), ranked_inventory AS (
                SELECT inventory_groups.*,
                       COUNT(*) OVER (PARTITION BY dimension) AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY dimension ORDER BY endpoints DESC
                       ) AS group_rank
                FROM inventory_groups
            )
            SELECT * FROM ranked_inventory
            WHERE dimension = 'coverage' OR group_rank <= {limit}
            ORDER BY dimension, group_rank
        """,
        "profiling": f"""
            WITH profiling_source AS (
                SELECT endpoint_id,
                       {profiling_dimensions["endpoint_profile"]} AS endpoint_profile,
                       {profiling_dimensions["source"]} AS source,
                       {profiling_dimensions["endpoint_action_name"]} AS endpoint_action_name,
                       {profiling_dimensions["identity_group"]} AS identity_group
                FROM profiled_endpoints_summary
                WHERE {profiling_recent}
            )
            SELECT grouped_profiling.*,
                   SUM(endpoints) OVER () AS total_memberships,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT endpoint_profile, source, endpoint_action_name, identity_group,
                       COUNT(DISTINCT endpoint_id) AS endpoints
                FROM profiling_source
                GROUP BY endpoint_profile, source, endpoint_action_name, identity_group
            ) grouped_profiling
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace reporting-inventory and bounded profiling snapshots."""
    with observe("dataconnect_endpoints"):
        rows = query_set(
            dataconnect,
            _queries(
                group_limit(cfg), event_window_hours(
                    cfg, getattr(cfg, "dataconnect_endpoints_interval", 21600)),
                getattr(dataconnect, "schema", None)),
        )
        coverage = next((row for row in rows["inventory"]
                         if row.get("dimension") == "coverage"), {})
        total = integer(coverage.get("endpoints"))
        profiles_rows = [row for row in rows["inventory"]
                         if row.get("dimension") == "profile"]
        identity_rows = [row for row in rows["inventory"]
                         if row.get("dimension") == "identity_group"]
        profile_summary = profiles_rows[0] if profiles_rows else {}
        group_summary = identity_rows[0] if identity_rows else {}
        profiling_summary = rows["profiling"][0] if rows["profiling"] else {}
        profile_groups = integer(profile_summary.get("total_groups"))
        identity_groups = integer(group_summary.get("total_groups"))
        profiling_groups = integer(profiling_summary.get("total_groups"))
        profiling_memberships = integer(profiling_summary.get("total_memberships"))
        profiles = [(label(row.get("dimension_value"), "Unknown"),
                     integer(row.get("endpoints"))) for row in profiles_rows]
        groups = [(label(row.get("dimension_value"), "none"),
                   integer(row.get("endpoints"))) for row in identity_rows]
        posture = [
            ("yes", integer(coverage.get("posture_yes"))),
            ("no", integer(coverage.get("posture_no"))),
        ]
        profiling = [{
            "profile": label(row.get("endpoint_profile"), "Unknown"),
            "source": label(row.get("source"), "Unknown"),
            "action": label(row.get("endpoint_action_name"), "none"),
            "group": label(row.get("identity_group"), "none"),
            "count": integer(row.get("endpoints")),
        } for row in rows["profiling"]]

        writers = []
        writers.extend((
            lambda: metrics.ise_dataconnect_endpoints_total.set(total),
            lambda: metrics.ise_dataconnect_profiled_endpoint_group_memberships_total.set(
                profiling_memberships),
        ))
        schema = getattr(dataconnect, "schema", None)
        if schema_has(schema, "ENDPOINTS_DATA", "endpoint_policy"):
            writers.append(
                lambda: metrics.ise_dataconnect_endpoints_unknown_profile_total.labels(
                    source_view="endpoints_data").set(
                    integer(coverage.get("unknown_profile"))))
        for field in ("hostname", "ip", "custom_attributes", "portal_user", "mdm", "udid"):
            source_column = {
                "hostname": "hostname", "ip": "endpoint_ip",
                "custom_attributes": "custom_attributes", "portal_user": "portal_user",
                "mdm": "mdm_guid", "udid": "native_udid",
            }[field]
            if not schema_has(schema, "ENDPOINTS_DATA", source_column):
                continue
            populated = integer(coverage.get(field))
            writers.extend((
                lambda field=field, populated=populated:
                    metrics.ise_dataconnect_endpoint_field_populated.labels(
                        field=field).set(populated),
                lambda field=field, populated=populated:
                    metrics.ise_dataconnect_endpoint_field_coverage_ratio.labels(
                        field=field).set(populated / total if total else 0),
            ))
        for age_days in (30, 90, 180):
            if not schema_has(schema, "ENDPOINTS_DATA", "update_time"):
                continue
            writers.append(
                lambda age_days=age_days: metrics.ise_dataconnect_endpoints_stale.labels(
                    age_days=str(age_days)).set(integer(coverage.get(f"stale_{age_days}"))))
        writers.extend(lambda profile=profile, count=count:
                       metrics.ise_dataconnect_endpoints_by_profile.labels(
                           profile=profile).set(count) for profile, count in profiles)
        writers.extend(lambda group=group, count=count:
                       metrics.ise_dataconnect_endpoints_by_identity_group.labels(
                           identity_group=group).set(count) for group, count in groups)
        if schema_has(schema, "ENDPOINTS_DATA", "posture_applicable"):
            writers.extend(lambda applicable=applicable, count=count:
                           metrics.ise_dataconnect_endpoints_by_posture_applicable.labels(
                               applicable=applicable).set(count) for applicable, count in posture)
        writers.extend(
            lambda row=row: metrics.ise_dataconnect_profile_events.labels(
                profile=row["profile"], source=row["source"], action=row["action"],
                identity_group=row["group"]).set(row["count"])
            for row in profiling
        )
        returned = {
            "profile": len(profiles),
            "identity_group": len(groups),
            "profiling": len(profiling),
        }
        available = {
            "profile": profile_groups,
            "identity_group": identity_groups,
            "profiling": profiling_groups,
        }
        for breakdown in returned:
            writers.extend((
                lambda breakdown=breakdown: metrics.ise_dataconnect_endpoint_topk_groups_returned.labels(
                    breakdown=breakdown).set(returned[breakdown]),
                lambda breakdown=breakdown: metrics.ise_dataconnect_endpoint_topk_groups_total.labels(
                    breakdown=breakdown).set(available[breakdown]),
                lambda breakdown=breakdown: metrics.ise_dataconnect_endpoint_topk_truncated.labels(
                    breakdown=breakdown).set(returned[breakdown] < available[breakdown]),
            ))
        replace_snapshot(_METRICS, writers)
