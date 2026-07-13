"""TACACS / Device Administration configuration and activity collectors.

ERS/OpenAPI owns configuration inventory. Data Connect owns per-account activity.
Cumulative policy hit counters are intentionally not exported because lifetime
totals look like current traffic and cannot provide account attribution.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .. import metrics
from ..util import clear_metric, normalize_bool_label
from . import CollectorFailed, observe


_CONFIG_METRICS = (
    metrics.ise_tacacs_internal_user_info,
    metrics.ise_tacacs_internal_user_created_timestamp,
    metrics.ise_tacacs_internal_user_modified_timestamp,
    metrics.ise_tacacs_suspected_unused_internal_user,
    metrics.ise_tacacs_internal_user_hygiene_risk,
    metrics.ise_tacacs_policy_objects_total,
)

_ACTIVITY_METRICS = (
    metrics.ise_tacacs_account_authentication_events,
    metrics.ise_tacacs_account_authorization_events,
    metrics.ise_tacacs_accounting_events,
    metrics.ise_tacacs_account_last_seen_timestamp,
)


def _timestamp(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _label(value):
    text = str(value or "").strip()
    return text or "none"


def _collect_dataconnect(dataconnect, cfg):
    limit = max(1, int(getattr(cfg, "dataconnect_max_groups", 5000)))
    queries = {
        "authentication": f"""
            SELECT username, status, device_name, authentication_policy,
                   identity_store, failure_reason, COUNT(*) AS hits,
                   MAX(epoch_time) AS last_seen
            FROM tacacs_authentication_last_two_days
            GROUP BY username, status, device_name, authentication_policy,
                     identity_store, failure_reason
            ORDER BY hits DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "authorization": f"""
            SELECT username, status, device_name, authorization_policy,
                   shell_profile, matched_command_set, command_from_device,
                   COUNT(*) AS hits, MAX(epoch_time) AS last_seen
            FROM tacacs_authorization_last_two_days
            GROUP BY username, status, device_name, authorization_policy,
                     shell_profile, matched_command_set, command_from_device
            ORDER BY hits DESC FETCH FIRST {limit} ROWS ONLY
        """,
        "accounting": f"""
            SELECT username, status, device_name,
                   TRIM(command || ' ' || command_args) AS command,
                   COUNT(*) AS hits, MAX(epoch_time) AS last_seen
            FROM tacacs_accounting_last_two_days
            GROUP BY username, status, device_name,
                     TRIM(command || ' ' || command_args)
            ORDER BY hits DESC FETCH FIRST {limit} ROWS ONLY
        """,
    }
    rows = {kind: dataconnect.query(sql) for kind, sql in queries.items()}

    for metric in _ACTIVITY_METRICS:
        clear_metric(metric)

    last_seen = {}
    for row in rows["authentication"]:
        username = _label(row.get("username"))
        metrics.ise_tacacs_account_authentication_events.labels(
            username=username,
            status=_label(row.get("status")),
            device=_label(row.get("device_name")),
            policy=_label(row.get("authentication_policy")),
            identity_store=_label(row.get("identity_store")),
            failure_reason=_label(row.get("failure_reason")),
        ).set(int(row.get("hits") or 0))
        last_seen[(username, "authentication")] = max(
            last_seen.get((username, "authentication"), 0), int(row.get("last_seen") or 0))

    for row in rows["authorization"]:
        username = _label(row.get("username"))
        metrics.ise_tacacs_account_authorization_events.labels(
            username=username,
            status=_label(row.get("status")),
            device=_label(row.get("device_name")),
            policy=_label(row.get("authorization_policy")),
            shell_profile=_label(row.get("shell_profile")),
            command_set=_label(row.get("matched_command_set")),
            command=_label(row.get("command_from_device")),
        ).set(int(row.get("hits") or 0))
        last_seen[(username, "authorization")] = max(
            last_seen.get((username, "authorization"), 0), int(row.get("last_seen") or 0))

    for row in rows["accounting"]:
        username = _label(row.get("username"))
        metrics.ise_tacacs_accounting_events.labels(
            username=username,
            status=_label(row.get("status")),
            device=_label(row.get("device_name")),
            command=_label(row.get("command")),
        ).set(int(row.get("hits") or 0))
        last_seen[(username, "accounting")] = max(
            last_seen.get((username, "accounting"), 0), int(row.get("last_seen") or 0))

    for (username, event_type), timestamp in last_seen.items():
        metrics.ise_tacacs_account_last_seen_timestamp.labels(
            username=username, event_type=event_type).set(timestamp)


def collect_config(client, cfg):
    with observe("tacacs_config"):
        resources = client.get_ers(
            "/config/internaluser", {"size": 100}, get_all=True,
            api_name="ers_tacacs_internal_users")
        policy_sets = client.get_pan_api(
            "/policy/device-admin/policy-set", api_name="tacacs_policy_sets")
        if resources is None and policy_sets is None:
            raise CollectorFailed("no TACACS internal-user or Device Admin policy data")

        resources = resources or []
        limit = max(0, getattr(cfg, "tacacs_internal_user_max", 1000))
        selected = resources[:limit] if limit else []

        def fetch(resource):
            user_id = resource.get("id") if isinstance(resource, dict) else None
            if not user_id:
                return None
            result = client.get_ers(
                f"/config/internaluser/{user_id}", api_name="ers_tacacs_internal_user_detail")
            detail = ((result or {}).get("InternalUser")
                      if isinstance(result, dict) else None)
            # The list row still contains a useful name/id when the per-user GET is
            # forbidden or transiently fails. Keep inventory panels populated and
            # expose detail coverage instead of silently dropping the account.
            merged = dict(resource) if isinstance(resource, dict) else {}
            if isinstance(detail, dict):
                merged.update(detail)
                merged["_detail_fetched"] = True
            return merged or None

        with ThreadPoolExecutor(max_workers=max(1, getattr(cfg, "max_workers", 10))) as pool:
            users = [user for user in pool.map(fetch, selected) if isinstance(user, dict)]

        policy_sets = policy_sets if isinstance(policy_sets, list) else []
        auth_rows = []
        authz_rows = []
        for policy_set in policy_sets:
            policy_id = policy_set.get("id")
            if not policy_id:
                continue
            authentication = client.get_pan_api(
                f"/policy/device-admin/policy-set/{policy_id}/authentication",
                api_name="tacacs_authentication_rules")
            authorization = client.get_pan_api(
                f"/policy/device-admin/policy-set/{policy_id}/authorization",
                api_name="tacacs_authorization_rules")
            auth_rows.extend((policy_set, row) for row in (authentication or [])
                             if isinstance(row, dict))
            authz_rows.extend((policy_set, row) for row in (authorization or [])
                              if isinstance(row, dict))

        command_sets = client.get_pan_api(
            "/policy/device-admin/command-sets", api_name="tacacs_command_sets")
        shell_profiles = client.get_pan_api(
            "/policy/device-admin/shell-profiles", api_name="tacacs_shell_profiles")

        for metric in _CONFIG_METRICS:
            clear_metric(metric)
        metrics.ise_tacacs_internal_users_total.set(len(resources))
        detail_count = sum(user.get("_detail_fetched") is True for user in users)
        metrics.ise_tacacs_internal_user_detail_coverage.set(
            detail_count / len(selected) if selected else 1.0)

        review_days = max(1, getattr(cfg, "tacacs_unused_account_days", 180))
        cutoff = datetime.now(timezone.utc).timestamp() - review_days * 86400
        for user in users:
            username = str(user.get("name") or "unknown")
            enabled = normalize_bool_label(user.get("enabled"))
            metrics.ise_tacacs_internal_user_info.labels(
                username=username,
                enabled=enabled,
                password_never_expires=normalize_bool_label(user.get("passwordNeverExpires")),
                change_password=normalize_bool_label(user.get("changePassword")),
                identity_store=str(user.get("passwordIDStore") or "unknown"),
            ).set(1)
            password_never_expires = normalize_bool_label(user.get("passwordNeverExpires"))
            if enabled == "true" and password_never_expires == "true":
                metrics.ise_tacacs_internal_user_hygiene_risk.labels(
                    username=username, risk="password_never_expires").set(1)
            if normalize_bool_label(user.get("changePassword")) == "true":
                metrics.ise_tacacs_internal_user_hygiene_risk.labels(
                    username=username, risk="change_password_required").set(1)
            for field, metric in (
                    ("dateCreated", metrics.ise_tacacs_internal_user_created_timestamp),
                    ("dateModified", metrics.ise_tacacs_internal_user_modified_timestamp)):
                timestamp = _timestamp(user.get(field))
                if timestamp is not None:
                    metric.labels(username=username).set(timestamp)
            modified = _timestamp(user.get("dateModified"))
            if enabled == "true" and modified is not None and modified < cutoff:
                metrics.ise_tacacs_suspected_unused_internal_user.labels(
                    username=username, reason=f"object_not_modified_{review_days}d").set(1)

        object_counts = {
            "policy_sets": len(policy_sets),
            "authentication_rules": len(auth_rows),
            "authorization_rules": len(authz_rows),
            "command_sets": len(command_sets) if isinstance(command_sets, list) else 0,
            "shell_profiles": len(shell_profiles) if isinstance(shell_profiles, list) else 0,
        }
        for object_type, count in object_counts.items():
            metrics.ise_tacacs_policy_objects_total.labels(object_type=object_type).set(count)


def collect_activity(dataconnect, cfg):
    with observe("tacacs_activity"):
        try:
            _collect_dataconnect(dataconnect, cfg)
            metrics.ise_tacacs_dataconnect_up.set(1)
        except Exception:
            metrics.ise_tacacs_dataconnect_up.set(0)
            raise
