"""TACACS / Device Administration inventory and policy-hit collector.

ISE's supported ERS/OpenAPI surfaces expose internal-user inventory and cumulative
Device Admin policy/rule hit counts, but not a per-account TACACS last-login time.
The suspected-unused signal is therefore intentionally conservative: enabled
internal users are candidates only when the deployment's Device Admin policy sets
have zero cumulative hits. The reason label makes that evidence explicit.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .. import metrics
from ..util import clear_metric, normalize_bool_label
from . import CollectorFailed, observe


_METRICS = (
    metrics.ise_tacacs_internal_user_info,
    metrics.ise_tacacs_internal_user_created_timestamp,
    metrics.ise_tacacs_internal_user_modified_timestamp,
    metrics.ise_tacacs_suspected_unused_internal_user,
    metrics.ise_tacacs_policy_set_hits,
    metrics.ise_tacacs_authentication_rule_hits,
    metrics.ise_tacacs_authorization_rule_hits,
    metrics.ise_tacacs_policy_objects_total,
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


def _rule(row):
    return row.get("rule", {}) if isinstance(row, dict) else {}


def _hit_count(row):
    try:
        return int(row.get("hitCounts") or 0)
    except (AttributeError, TypeError, ValueError):
        return 0


def collect(client, cfg):
    with observe("tacacs"):
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
            return (result or {}).get("InternalUser") if isinstance(result, dict) else None

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

        for metric in _METRICS:
            clear_metric(metric)
        metrics.ise_tacacs_internal_users_total.set(len(resources))

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
            for field, metric in (
                    ("dateCreated", metrics.ise_tacacs_internal_user_created_timestamp),
                    ("dateModified", metrics.ise_tacacs_internal_user_modified_timestamp)):
                timestamp = _timestamp(user.get(field))
                if timestamp is not None:
                    metric.labels(username=username).set(timestamp)

        total_policy_hits = sum(_hit_count(policy_set) for policy_set in policy_sets)
        if policy_sets and total_policy_hits == 0:
            for user in users:
                if normalize_bool_label(user.get("enabled")) == "true":
                    metrics.ise_tacacs_suspected_unused_internal_user.labels(
                        username=str(user.get("name") or "unknown"),
                        reason="no_device_admin_policy_hits").set(1)

        for policy_set in policy_sets:
            metrics.ise_tacacs_policy_set_hits.labels(
                policy_set=str(policy_set.get("name") or "unknown"),
                state=str(policy_set.get("state") or "unknown"),
                service=str(policy_set.get("serviceName") or "unknown"),
            ).set(_hit_count(policy_set))

        for policy_set, row in auth_rows:
            rule = _rule(row)
            metrics.ise_tacacs_authentication_rule_hits.labels(
                policy_set=str(policy_set.get("name") or "unknown"),
                rule=str(rule.get("name") or "unknown"),
                state=str(rule.get("state") or "unknown"),
                identity_source=str(row.get("identitySourceName") or "unknown"),
            ).set(_hit_count(rule))

        for policy_set, row in authz_rows:
            rule = _rule(row)
            commands = row.get("commands") or []
            metrics.ise_tacacs_authorization_rule_hits.labels(
                policy_set=str(policy_set.get("name") or "unknown"),
                rule=str(rule.get("name") or "unknown"),
                state=str(rule.get("state") or "unknown"),
                profile=str(row.get("profile") or "unknown"),
                command_sets=",".join(str(command) for command in commands) or "none",
            ).set(_hit_count(rule))

        object_counts = {
            "policy_sets": len(policy_sets),
            "authentication_rules": len(auth_rows),
            "authorization_rules": len(authz_rows),
            "command_sets": len(command_sets) if isinstance(command_sets, list) else 0,
            "shell_profiles": len(shell_profiles) if isinstance(shell_profiles, list) else 0,
        }
        for object_type, count in object_counts.items():
            metrics.ise_tacacs_policy_objects_total.labels(object_type=object_type).set(count)
