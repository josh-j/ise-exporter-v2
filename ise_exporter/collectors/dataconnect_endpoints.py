"""Endpoint inventory and profiling reporting from Cisco ISE Data Connect."""
from .. import metrics
from . import observe
from .dataconnect_common import (
    event_window_hours,
    group_limit,
    integer,
    label,
    recent_event_predicate,
    replace_snapshot,
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


def _queries(limit, window_hours=6):
    profiling_recent = recent_event_predicate("timestamp", window_hours)
    return {
        "coverage": """
            SELECT COUNT(*) AS endpoints,
                   SUM(CASE WHEN TRIM(hostname) IS NOT NULL THEN 1 ELSE 0 END) AS hostname,
                   SUM(CASE WHEN TRIM(endpoint_ip) IS NOT NULL THEN 1 ELSE 0 END) AS ip,
                   SUM(CASE WHEN TRIM(custom_attributes) IS NOT NULL THEN 1 ELSE 0 END)
                       AS custom_attributes,
                   SUM(CASE WHEN TRIM(portal_user) IS NOT NULL THEN 1 ELSE 0 END)
                       AS portal_user,
                   SUM(CASE WHEN TRIM(mdm_guid) IS NOT NULL THEN 1 ELSE 0 END) AS mdm,
                   SUM(CASE WHEN TRIM(native_udid) IS NOT NULL THEN 1 ELSE 0 END) AS udid,
                   SUM(CASE WHEN NVL(posture_applicable, 0) = 1 THEN 1 ELSE 0 END)
                       AS posture_yes,
                   SUM(CASE WHEN NVL(posture_applicable, 0) = 1 THEN 0 ELSE 1 END)
                       AS posture_no,
                   SUM(CASE WHEN TRIM(endpoint_policy) IS NULL
                                  OR LOWER(TRIM(endpoint_policy)) IN
                                      ('unknown', 'none', 'missing')
                            THEN 1 ELSE 0 END) AS unknown_profile,
                   SUM(CASE WHEN update_time < SYSTIMESTAMP - NUMTODSINTERVAL(30, 'DAY')
                            OR update_time IS NULL THEN 1 ELSE 0 END) AS stale_30,
                   SUM(CASE WHEN update_time < SYSTIMESTAMP - NUMTODSINTERVAL(90, 'DAY')
                            OR update_time IS NULL THEN 1 ELSE 0 END) AS stale_90,
                   SUM(CASE WHEN update_time < SYSTIMESTAMP - NUMTODSINTERVAL(180, 'DAY')
                            OR update_time IS NULL THEN 1 ELSE 0 END) AS stale_180
            FROM endpoints_data
        """,
        "dimensions": f"""
            WITH dimension_groups AS (
                SELECT CASE WHEN GROUPING(endpoint_policy) = 0
                            THEN 'profile' ELSE 'identity_group' END AS dimension,
                       CASE WHEN GROUPING(endpoint_policy) = 0
                            THEN endpoint_policy ELSE identity_group_id END AS dimension_value,
                       COUNT(*) AS endpoints
                FROM endpoints_data
                GROUP BY GROUPING SETS ((endpoint_policy), (identity_group_id))
            ), ranked_dimensions AS (
                SELECT dimension, dimension_value, endpoints,
                       COUNT(*) OVER (PARTITION BY dimension) AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY dimension ORDER BY endpoints DESC
                       ) AS group_rank
                FROM dimension_groups
            )
            SELECT dimension, dimension_value, endpoints, total_groups
            FROM ranked_dimensions
            WHERE group_rank <= {limit}
            ORDER BY dimension, group_rank
        """,
        "profiling": f"""
            SELECT grouped_profiling.*,
                   SUM(endpoints) OVER () AS total_memberships,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT endpoint_profile, source, endpoint_action_name, identity_group,
                       COUNT(DISTINCT endpoint_id) AS endpoints
                FROM profiled_endpoints_summary
                WHERE {profiling_recent}
                GROUP BY endpoint_profile, source, endpoint_action_name, identity_group
            ) grouped_profiling
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace current inventory and bounded profiling snapshots."""
    with observe("dataconnect_endpoints"):
        rows = {name: dataconnect.query(sql)
                for name, sql in _queries(
                    group_limit(cfg), event_window_hours(
                        cfg, getattr(cfg, "dataconnect_endpoints_interval", 86400))).items()}
        coverage = rows["coverage"][0] if rows["coverage"] else {}
        total = integer(coverage.get("endpoints"))
        profiles_rows = [row for row in rows["dimensions"]
                         if row.get("dimension") == "profile"]
        identity_rows = [row for row in rows["dimensions"]
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
            lambda: metrics.ise_dataconnect_endpoints_unknown_profile_total.set(
                integer(coverage.get("unknown_profile"))),
            lambda: metrics.ise_dataconnect_profiled_endpoint_group_memberships_total.set(
                profiling_memberships),
        ))
        for field in ("hostname", "ip", "custom_attributes", "portal_user", "mdm", "udid"):
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
            writers.append(
                lambda age_days=age_days: metrics.ise_dataconnect_endpoints_stale.labels(
                    age_days=str(age_days)).set(integer(coverage.get(f"stale_{age_days}"))))
        writers.extend(lambda profile=profile, count=count:
                       metrics.ise_dataconnect_endpoints_by_profile.labels(
                           profile=profile).set(count) for profile, count in profiles)
        writers.extend(lambda group=group, count=count:
                       metrics.ise_dataconnect_endpoints_by_identity_group.labels(
                           identity_group=group).set(count) for group, count in groups)
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
