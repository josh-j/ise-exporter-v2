"""Endpoint inventory and profiling reporting from Cisco ISE Data Connect."""
from .. import metrics
from . import observe
from .dataconnect_common import group_limit, integer, label, replace_snapshot


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


def _queries(limit):
    return {
        "total": "SELECT COUNT(*) AS endpoints FROM endpoints_data",
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
        "profiles": f"""
            SELECT grouped_profiles.*, COUNT(*) OVER () AS total_groups
            FROM (
                SELECT endpoint_policy, COUNT(*) AS endpoints
                FROM endpoints_data GROUP BY endpoint_policy
            ) grouped_profiles
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "groups": f"""
            SELECT grouped_identity.*, COUNT(*) OVER () AS total_groups
            FROM (
                SELECT identity_group_id, COUNT(*) AS endpoints
                FROM endpoints_data GROUP BY identity_group_id
            ) grouped_identity
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "posture": """
            SELECT CASE WHEN NVL(posture_applicable, 0) = 1 THEN 'yes' ELSE 'no' END AS applicable,
                   COUNT(*) AS endpoints
            FROM endpoints_data
            GROUP BY CASE WHEN NVL(posture_applicable, 0) = 1 THEN 'yes' ELSE 'no' END
        """,
        "profiling": f"""
            SELECT grouped_profiling.*,
                   SUM(endpoints) OVER () AS total_memberships,
                   COUNT(*) OVER () AS total_groups
            FROM (
                SELECT endpoint_profile, source, endpoint_action_name, identity_group,
                       COUNT(DISTINCT endpoint_id) AS endpoints
                FROM profiled_endpoints_summary
                WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
                GROUP BY endpoint_profile, source, endpoint_action_name, identity_group
            ) grouped_profiling
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace current inventory and bounded profiling snapshots."""
    with observe("dataconnect_endpoints"):
        rows = {name: dataconnect.query(sql)
                for name, sql in _queries(group_limit(cfg)).items()}
        total = integer(rows["total"][0].get("endpoints")) if rows["total"] else 0
        coverage = rows["coverage"][0] if rows["coverage"] else {}
        profile_summary = rows["profiles"][0] if rows["profiles"] else {}
        group_summary = rows["groups"][0] if rows["groups"] else {}
        profiling_summary = rows["profiling"][0] if rows["profiling"] else {}
        profile_groups = integer(profile_summary.get("total_groups"))
        identity_groups = integer(group_summary.get("total_groups"))
        profiling_groups = integer(profiling_summary.get("total_groups"))
        profiling_memberships = integer(profiling_summary.get("total_memberships"))
        profiles = [(label(row.get("endpoint_policy"), "Unknown"),
                     integer(row.get("endpoints"))) for row in rows["profiles"]]
        groups = [(label(row.get("identity_group_id"), "none"),
                   integer(row.get("endpoints"))) for row in rows["groups"]]
        posture = [(label(row.get("applicable")), integer(row.get("endpoints")))
                   for row in rows["posture"]]
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
