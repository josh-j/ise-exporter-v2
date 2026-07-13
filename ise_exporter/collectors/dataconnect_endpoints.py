"""Endpoint inventory and profiling reporting from Cisco ISE Data Connect."""
from .. import metrics
from . import observe
from .dataconnect_common import group_limit, integer, label, replace_snapshot


_METRICS = (
    metrics.ise_dataconnect_endpoints_by_profile,
    metrics.ise_dataconnect_endpoints_by_identity_group,
    metrics.ise_dataconnect_endpoints_by_posture_applicable,
    metrics.ise_dataconnect_profile_events,
)


def _queries(limit):
    return {
        "total": "SELECT COUNT(*) AS endpoints FROM endpoints_data",
        "profiles": f"""
            SELECT endpoint_policy, COUNT(*) AS endpoints
            FROM endpoints_data GROUP BY endpoint_policy
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "groups": f"""
            SELECT identity_group_id, COUNT(*) AS endpoints
            FROM endpoints_data GROUP BY identity_group_id
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "posture": """
            SELECT CASE WHEN NVL(posture_applicable, 0) = 1 THEN 'yes' ELSE 'no' END AS applicable,
                   COUNT(*) AS endpoints
            FROM endpoints_data
            GROUP BY CASE WHEN NVL(posture_applicable, 0) = 1 THEN 'yes' ELSE 'no' END
        """,
        "profiling": f"""
            SELECT endpoint_profile, source, endpoint_action_name, identity_group,
                   COUNT(DISTINCT endpoint_id) AS endpoints
            FROM profiled_endpoints_summary
            WHERE timestamp >= SYSTIMESTAMP - INTERVAL '2' DAY
            GROUP BY endpoint_profile, source, endpoint_action_name, identity_group
            ORDER BY endpoints DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }


def collect(dataconnect, cfg):
    """Atomically replace current inventory and bounded profiling snapshots."""
    with observe("dataconnect_endpoints"):
        rows = {name: dataconnect.query(sql)
                for name, sql in _queries(group_limit(cfg)).items()}
        total = integer(rows["total"][0].get("endpoints")) if rows["total"] else 0
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
        replace_snapshot(_METRICS, writers)
        metrics.ise_dataconnect_endpoints_total.set(total)
