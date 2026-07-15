"""TACACS / Device Administration configuration and activity collectors.

ERS/OpenAPI owns configuration inventory. Data Connect owns per-account activity.
Cumulative policy hit counters are intentionally not exported because lifetime
totals look like current traffic and cannot provide account attribution.
"""
from datetime import datetime, timezone
import json
import logging
import time

from .. import metrics
from ..state import StateStore
from ..util import metric_label, normalize_bool_label
from . import CollectorFailed, observe
from .dataconnect_common import (
    event_window_hours,
    group_limit,
    query_set,
    replace_snapshot,
)


_CONFIG_METRICS = (
    metrics.ise_tacacs_internal_users_total,
    metrics.ise_tacacs_internal_user_inventory_selected,
    metrics.ise_tacacs_internal_user_inventory_truncated,
    metrics.ise_tacacs_internal_user_detail_coverage,
    metrics.ise_tacacs_internal_user_detail_cache_entries,
    metrics.ise_tacacs_internal_user_detail_refresh_requests,
    metrics.ise_tacacs_internal_user_detail_refresh_failures,
    metrics.ise_tacacs_internal_user_detail_refresh_deferred,
    metrics.ise_tacacs_internal_user_info,
    metrics.ise_tacacs_internal_user_created_timestamp,
    metrics.ise_tacacs_internal_user_modified_timestamp,
    metrics.ise_tacacs_suspected_unused_internal_user,
    metrics.ise_tacacs_unused_account_review_seconds,
    metrics.ise_tacacs_internal_user_hygiene_risk,
    metrics.ise_tacacs_policy_objects_total,
)

_INTERNAL_USERS_STATE = "tacacs.internal_users"
_INTERNAL_LAST_SEEN_STATE = "tacacs.internal_last_seen"
_INTERNAL_USER_DETAIL_FIELDS = (
    "id", "name", "enabled", "passwordNeverExpires", "changePassword",
    "passwordIDStore", "dateCreated", "dateModified",
)
_EVENT_TYPES = ("authentication", "authorization", "accounting")
logger = logging.getLogger(__name__)


def _object_list(value, description):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise CollectorFailed(f"{description} returned an invalid object list")
    return value


def _state_path(cfg):
    return getattr(cfg, "state_db_path", ":memory:")


def _load_json(store, key, default):
    try:
        value = json.loads(store.get_value(key, ""))
    except (TypeError, ValueError):
        return default
    return value


def _sync_internal_user_state(cfg, accounts):
    """Persist bounded raw-to-metric internal names and their activity high water."""
    accounts = {label: raw for raw, label in accounts}
    store = StateStore(_state_path(cfg))
    try:
        previous = _load_json(store, _INTERNAL_LAST_SEEN_STATE, {})
        high_water = {
            username: {
                event_type: int(events[event_type])
                for event_type in _EVENT_TYPES
                if isinstance(events, dict) and event_type in events
                and str(events[event_type]).isdigit()
            }
            for username in accounts
            if isinstance(previous, dict) and isinstance(previous.get(username), dict)
            for events in (previous[username],)
        }
        store.set_value(_INTERNAL_USERS_STATE, json.dumps(accounts, separators=(",", ":")),
                        commit=False)
        store.set_value(_INTERNAL_LAST_SEEN_STATE,
                        json.dumps(high_water, separators=(",", ":")), commit=False)
        store.commit()
        return high_water
    finally:
        store.close()


def _internal_accounts(cfg):
    """Return at most 1,000 ``(metric_label, raw_casefolded_name)`` pairs."""
    store = StateStore(_state_path(cfg))
    try:
        saved = _load_json(store, _INTERNAL_USERS_STATE, {})
    finally:
        store.close()
    if isinstance(saved, dict):
        pairs = ((str(label), str(raw).strip().casefold())
                 for label, raw in saved.items())
    elif isinstance(saved, list):
        # Upgrade legacy state which stored only the already-normalized label.
        pairs = ((str(value), str(value).strip().casefold()) for value in saved)
    else:
        return []
    return sorted({(label, raw) for label, raw in pairs if label.strip() and raw})[:1000]


def _merge_internal_last_seen(cfg, observed):
    """Merge at most three timestamps per configured internal account."""
    store = StateStore(_state_path(cfg))
    try:
        usernames = _load_json(store, _INTERNAL_USERS_STATE, [])
        if isinstance(usernames, dict):
            internal = {str(value) for value in usernames if str(value).strip()}
        elif isinstance(usernames, list):
            internal = {str(value) for value in usernames if str(value).strip()}
        else:
            internal = set()
        previous = _load_json(store, _INTERNAL_LAST_SEEN_STATE, {})
        high_water = {}
        for username in internal:
            saved = previous.get(username, {}) if isinstance(previous, dict) else {}
            high_water[username] = {
                event_type: int(saved[event_type])
                for event_type in _EVENT_TYPES
                if isinstance(saved, dict) and event_type in saved
                and str(saved[event_type]).isdigit()
            }
        for (username, event_type), timestamp in observed.items():
            if username in internal and event_type in _EVENT_TYPES and timestamp > 0:
                high_water[username][event_type] = max(
                    high_water[username].get(event_type, 0), int(timestamp))
        store.set_value(_INTERNAL_LAST_SEEN_STATE,
                        json.dumps(high_water, separators=(",", ":")))
        return high_water
    finally:
        store.close()

_ACTIVITY_METRICS = (
    metrics.ise_tacacs_account_authentication_events,
    metrics.ise_tacacs_account_authorization_events,
    metrics.ise_tacacs_accounting_events,
    metrics.ise_tacacs_account_last_seen_timestamp,
    metrics.ise_tacacs_events_total,
    metrics.ise_tacacs_topk_groups_returned,
    metrics.ise_tacacs_topk_groups_total,
    metrics.ise_tacacs_topk_truncated,
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
    return metric_label(value, "none")


_FAILURE_CLASS_SQL = """CASE
    WHEN TRIM(failure_reason) IS NULL THEN 'none'
    WHEN LOWER(failure_reason) LIKE '%password%'
      OR LOWER(failure_reason) LIKE '%credential%'
      OR LOWER(failure_reason) LIKE '%authentication failed%' THEN 'credentials'
    WHEN LOWER(failure_reason) LIKE '%identity store%'
      OR LOWER(failure_reason) LIKE '%user not found%'
      OR LOWER(failure_reason) LIKE '%unknown user%' THEN 'identity_store'
    WHEN LOWER(failure_reason) LIKE '%denied%'
      OR LOWER(failure_reason) LIKE '%reject%'
      OR LOWER(failure_reason) LIKE '%policy%'
      OR LOWER(failure_reason) LIKE '%not permitted%' THEN 'policy_denied'
    WHEN LOWER(failure_reason) LIKE '%timeout%'
      OR LOWER(failure_reason) LIKE '%timed out%'
      OR LOWER(failure_reason) LIKE '%no response%' THEN 'timeout'
    WHEN LOWER(failure_reason) LIKE '%protocol%'
      OR LOWER(failure_reason) LIKE '%tacacs%' THEN 'protocol'
    ELSE 'other' END"""

_COMMAND_FAMILY_SQL = """CASE
    WHEN TRIM(command) IS NULL THEN 'none'
    WHEN LOWER(TRIM(command)) IN
      ('show', 'configure', 'interface', 'router', 'clear', 'debug',
       'copy', 'write', 'ping', 'traceroute', 'terminal', 'no')
      THEN LOWER(TRIM(command))
    ELSE 'other' END"""


def _activity_queries(limit, cutoff_epoch=None, internal_user_count=0):
    recent = "WHERE epoch_time >= :minimum_epoch" if cutoff_epoch is not None else ""
    internal_user_count = max(0, min(1000, int(internal_user_count)))
    internal_filter = ", ".join(
        f":internal_user_{index}" for index in range(internal_user_count))

    def selection(grouped, name):
        detail = f"(breakdown = 'detail' AND group_rank <= {limit})"
        internal = (" OR (breakdown = 'internal_last_seen' "
                    f"AND LOWER(TRIM(username)) IN ({internal_filter}))") \
            if internal_filter else ""
        return f"SELECT * FROM {grouped} WHERE {detail}{internal}"

    return {
        "authentication": f"""
            WITH grouped_auth AS (
                SELECT CASE WHEN GROUPING(status) = 1
                            THEN 'internal_last_seen' ELSE 'detail' END AS breakdown,
                       username, status, device_name, authentication_policy,
                       identity_store, {_FAILURE_CLASS_SQL} AS failure_class,
                       COUNT(*) AS hits, MAX(epoch_time) AS last_seen
                FROM tacacs_authentication_last_two_days
                {recent}
                GROUP BY GROUPING SETS (
                    (username, status, device_name, authentication_policy,
                     identity_store, {_FAILURE_CLASS_SQL}),
                    (username)
                )
            ), ranked_auth AS (
                SELECT grouped_auth.*,
                       SUM(CASE WHEN breakdown = 'detail' THEN hits ELSE 0 END)
                           OVER () AS total_events,
                       SUM(CASE WHEN breakdown = 'detail' THEN 1 ELSE 0 END)
                           OVER () AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown ORDER BY hits DESC) AS group_rank
                FROM grouped_auth
            )
            {selection("ranked_auth", "authentication")}
        """,
        "authorization": f"""
            WITH grouped_authorization AS (
                SELECT CASE WHEN GROUPING(status) = 1
                            THEN 'internal_last_seen' ELSE 'detail' END AS breakdown,
                       username, status, device_name, authorization_policy,
                       shell_profile, matched_command_set,
                       COUNT(*) AS hits, MAX(epoch_time) AS last_seen
                FROM tacacs_authorization_last_two_days
                {recent}
                GROUP BY GROUPING SETS (
                    (username, status, device_name, authorization_policy,
                     shell_profile, matched_command_set),
                    (username)
                )
            ), ranked_authorization AS (
                SELECT grouped_authorization.*,
                       SUM(CASE WHEN breakdown = 'detail' THEN hits ELSE 0 END)
                           OVER () AS total_events,
                       SUM(CASE WHEN breakdown = 'detail' THEN 1 ELSE 0 END)
                           OVER () AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown ORDER BY hits DESC) AS group_rank
                FROM grouped_authorization
            )
            {selection("ranked_authorization", "authorization")}
        """,
        "accounting": f"""
            WITH grouped_accounting AS (
                SELECT CASE WHEN GROUPING(status) = 1
                            THEN 'internal_last_seen' ELSE 'detail' END AS breakdown,
                       username, status, device_name,
                       {_COMMAND_FAMILY_SQL} AS command_family,
                       COUNT(*) AS hits, MAX(epoch_time) AS last_seen
                FROM tacacs_accounting_last_two_days
                {recent}
                GROUP BY GROUPING SETS (
                    (username, status, device_name, {_COMMAND_FAMILY_SQL}),
                    (username)
                )
            ), ranked_accounting AS (
                SELECT grouped_accounting.*,
                       SUM(CASE WHEN breakdown = 'detail' THEN hits ELSE 0 END)
                           OVER () AS total_events,
                       SUM(CASE WHEN breakdown = 'detail' THEN 1 ELSE 0 END)
                           OVER () AS total_groups,
                       ROW_NUMBER() OVER (
                           PARTITION BY breakdown ORDER BY hits DESC) AS group_rank
                FROM grouped_accounting
            )
            {selection("ranked_accounting", "accounting")}
        """,
    }


def _collect_dataconnect(dataconnect, cfg):
    limit = group_limit(cfg)
    window = event_window_hours(
        cfg, getattr(cfg, "dataconnect_tacacs_interval", 86400))
    cutoff = max(0, int(time.time()) - window * 3600)
    internal_accounts = _internal_accounts(cfg)
    parameters = {"minimum_epoch": cutoff}
    parameters.update({f"internal_user_{index}": raw
                       for index, (_label_name, raw) in enumerate(internal_accounts)})
    queries = _activity_queries(limit, cutoff, len(internal_accounts))
    combined = query_set(
        dataconnect, queries, {kind: parameters for kind in queries})
    rows = {kind: [row for row in values
                   if row.get("breakdown") != "internal_last_seen"]
            for kind, values in combined.items()}
    observed_last_seen = {}
    for event_type, event_rows in combined.items():
        for row in event_rows:
            username = _label(row.get("username"))
            observed_last_seen[(username, event_type)] = max(
                observed_last_seen.get((username, event_type), 0),
                int(row.get("last_seen") or 0))
    try:
        internal_last_seen = _merge_internal_last_seen(cfg, observed_last_seen)
    except Exception as exc:
        logger.warning("could not persist bounded TACACS activity high-water state: %s", exc)
        internal_last_seen = {}

    def publish():
        for row in rows["authentication"]:
            username = _label(row.get("username"))
            metrics.ise_tacacs_account_authentication_events.labels(
                username=username,
                status=_label(row.get("status")),
                device=_label(row.get("device_name")),
                policy=_label(row.get("authentication_policy")),
                identity_store=_label(row.get("identity_store")),
                failure_class=_label(row.get("failure_class")),
            ).set(int(row.get("hits") or 0))

        for row in rows["authorization"]:
            username = _label(row.get("username"))
            metrics.ise_tacacs_account_authorization_events.labels(
                username=username,
                status=_label(row.get("status")),
                device=_label(row.get("device_name")),
                policy=_label(row.get("authorization_policy")),
                shell_profile=_label(row.get("shell_profile")),
                command_set=_label(row.get("matched_command_set")),
            ).set(int(row.get("hits") or 0))

        for row in rows["accounting"]:
            username = _label(row.get("username"))
            metrics.ise_tacacs_accounting_events.labels(
                username=username,
                status=_label(row.get("status")),
                device=_label(row.get("device_name")),
                command_family=_label(row.get("command_family")),
            ).set(int(row.get("hits") or 0))
        published_last_seen = dict(observed_last_seen)
        for username, events in internal_last_seen.items():
            for event_type, timestamp in events.items():
                published_last_seen[(username, event_type)] = max(
                    published_last_seen.get((username, event_type), 0), timestamp)
        for (username, event_type), timestamp in published_last_seen.items():
            metrics.ise_tacacs_account_last_seen_timestamp.labels(
                username=username, event_type=event_type).set(timestamp)

        for event_type in _EVENT_TYPES:
            summary = rows[event_type][0] if rows[event_type] else {}
            total_events = int(summary.get("total_events") or 0)
            total_groups = int(summary.get("total_groups") or 0)
            returned = len(rows[event_type])
            metrics.ise_tacacs_events_total.labels(event_type=event_type).set(total_events)
            metrics.ise_tacacs_topk_groups_returned.labels(
                event_type=event_type).set(returned)
            metrics.ise_tacacs_topk_groups_total.labels(
                event_type=event_type).set(total_groups)
            metrics.ise_tacacs_topk_truncated.labels(
                event_type=event_type).set(returned < total_groups)

    replace_snapshot(_ACTIVITY_METRICS, (publish,))


def collect_config(client, cfg):
    with observe("tacacs_config"):
        resources = client.get_ers(
            "/config/internaluser", {"size": 100}, get_all=True,
            api_name="ers_tacacs_internal_users")
        policy_sets = client.get_pan_api(
            "/policy/device-admin/policy-set", api_name="tacacs_policy_sets")
        _object_list(resources, "TACACS internal-user inventory")
        _object_list(policy_sets, "Device Admin policy-set inventory")
        resource_ids = [str(row.get("id") or "").strip() for row in resources]
        if (any(not user_id or not str(row.get("name") or "").strip()
                for user_id, row in zip(resource_ids, resources))
                or any(len(str(row.get("name") or "").encode("utf-8")) > 256
                       for row in resources)
                or len(set(resource_ids)) != len(resource_ids)):
            raise CollectorFailed("TACACS internal-user inventory contained invalid identities")
        policy_ids = [str(row.get("id") or "").strip() for row in policy_sets]
        if any(not policy_id for policy_id in policy_ids) \
                or len(set(policy_ids)) != len(policy_ids):
            raise CollectorFailed("Device Admin policy-set inventory contained invalid IDs")
        limit = max(1, min(1000, int(getattr(cfg, "tacacs_internal_user_max", 1000))))
        ordered_resources = sorted(
            resources,
            key=lambda resource: (
                str(resource.get("name") or "").casefold(),
                str(resource.get("id") or ""),
            ) if isinstance(resource, dict) else ("", ""),
        )
        selected = ordered_resources[:limit]
        now = time.time()
        refresh_ttl = max(
            86400, int(getattr(cfg, "tacacs_internal_user_detail_ttl", 604800)))
        refresh_limit = max(1, min(250, int(getattr(
            cfg, "tacacs_internal_user_detail_max_requests", 100))))
        request_interval = max(0, int(getattr(
            cfg, "tacacs_internal_user_detail_request_interval_ms", 0))) / 1000
        selected_by_id = {
            str(resource["id"]): resource for resource in selected
            if isinstance(resource, dict) and resource.get("id")
        }
        store = StateStore(_state_path(cfg))
        try:
            cached = store.tacacs_user_entries(selected_by_id)
            refresh_candidates = sorted(
                selected_by_id,
                key=lambda user_id: (
                    user_id in cached,
                    cached.get(user_id, {}).get("updated_at", 0),
                    user_id,
                ),
            )
            refresh_candidates = [
                user_id for user_id in refresh_candidates
                if user_id not in cached
                or cached[user_id]["updated_at"] <= now - refresh_ttl
            ]
            refresh_ids = refresh_candidates[:refresh_limit]
            refresh_failures = 0
            refresh_requests = 0
            for user_id in refresh_ids:
                if refresh_requests and request_interval:
                    time.sleep(request_interval)
                refresh_requests += 1
                try:
                    result = client.get_ers(
                        f"/config/internaluser/{user_id}",
                        api_name="ers_tacacs_internal_user_detail")
                except Exception as exc:
                    result = None
                    logger.warning("internal-user detail refresh raised for %s: %s",
                                   user_id, exc)
                detail = result.get("InternalUser") if isinstance(result, dict) else None
                if not isinstance(detail, dict):
                    refresh_failures += 1
                    logger.warning(
                        "internal-user detail refresh failed for %s; retaining cached value",
                        user_id)
                    if refresh_failures >= 3:
                        logger.warning(
                            "stopping internal-user detail refresh after three failures")
                        break
                    continue
                detail = {field: detail[field] for field in _INTERNAL_USER_DETAIL_FIELDS
                          if field in detail}
                store.put_tacacs_user(user_id, detail, now)
                cached[user_id] = {"detail": detail, "updated_at": now}
            store.finish_tacacs_user_cycle(selected_by_id, now)
            cache_entries = store.tacacs_user_count()
        finally:
            store.close()

        users = []
        for user_id, resource in selected_by_id.items():
            entry = cached.get(user_id)
            if not entry:
                continue
            merged = dict(resource)
            merged.update(entry["detail"])
            users.append(merged)
        refresh_deferred = max(0, len(refresh_candidates) - refresh_requests)

        auth_rows = []
        authz_rows = []
        for policy_set in policy_sets:
            policy_id = policy_set.get("id")
            authentication = client.get_pan_api(
                f"/policy/device-admin/policy-set/{policy_id}/authentication",
                api_name="tacacs_authentication_rules")
            authorization = client.get_pan_api(
                f"/policy/device-admin/policy-set/{policy_id}/authorization",
                api_name="tacacs_authorization_rules")
            _object_list(authentication, f"Device Admin authentication rules for {policy_id}")
            _object_list(authorization, f"Device Admin authorization rules for {policy_id}")
            auth_rows.extend((policy_set, row) for row in authentication)
            authz_rows.extend((policy_set, row) for row in authorization)

        command_sets = client.get_pan_api(
            "/policy/device-admin/command-sets", api_name="tacacs_command_sets")
        shell_profiles = client.get_pan_api(
            "/policy/device-admin/shell-profiles", api_name="tacacs_shell_profiles")
        _object_list(command_sets, "Device Admin command-set inventory")
        _object_list(shell_profiles, "Device Admin shell-profile inventory")

        detail_count = len(users)
        review_days = max(1, getattr(cfg, "tacacs_unused_account_days", 180))
        cutoff = datetime.now(timezone.utc).timestamp() - review_days * 86400
        usernames = [
            (str(resource.get("name")).strip(), _label(resource.get("name")))
            for resource in selected if resource.get("name")
        ]
        try:
            internal_last_seen = _sync_internal_user_state(cfg, usernames)
        except Exception as exc:
            logger.warning("could not persist bounded TACACS internal-user state: %s", exc)
            internal_last_seen = {}
        object_counts = {
            "policy_sets": len(policy_sets),
            "authentication_rules": len(auth_rows),
            "authorization_rules": len(authz_rows),
            "command_sets": len(command_sets),
            "shell_profiles": len(shell_profiles),
        }

        def publish():
            metrics.ise_tacacs_internal_users_total.set(len(resources))
            metrics.ise_tacacs_internal_user_inventory_selected.set(len(selected_by_id))
            metrics.ise_tacacs_internal_user_inventory_truncated.set(
                max(0, len(resources) - len(selected_by_id)))
            metrics.ise_tacacs_internal_user_detail_coverage.set(
                detail_count / len(resources) if resources else 1.0)
            metrics.ise_tacacs_internal_user_detail_cache_entries.set(cache_entries)
            metrics.ise_tacacs_internal_user_detail_refresh_requests.set(refresh_requests)
            metrics.ise_tacacs_internal_user_detail_refresh_failures.set(refresh_failures)
            metrics.ise_tacacs_internal_user_detail_refresh_deferred.set(refresh_deferred)
            metrics.ise_tacacs_unused_account_review_seconds.set(review_days * 86400)
            for user in users:
                username = _label(user.get("name"))
                enabled = normalize_bool_label(user.get("enabled"))
                password_never_expires = normalize_bool_label(user.get("passwordNeverExpires"))
                change_password = normalize_bool_label(user.get("changePassword"))
                metrics.ise_tacacs_internal_user_info.labels(
                    username=username, enabled=enabled,
                    password_never_expires=password_never_expires,
                    change_password=change_password,
                    identity_store=_label(user.get("passwordIDStore"))).set(1)
                if enabled == "true" and password_never_expires == "true":
                    metrics.ise_tacacs_internal_user_hygiene_risk.labels(
                        username=username, risk="password_never_expires").set(1)
                if change_password == "true":
                    metrics.ise_tacacs_internal_user_hygiene_risk.labels(
                        username=username, risk="change_password_required").set(1)
                for field, metric in (
                        ("dateCreated", metrics.ise_tacacs_internal_user_created_timestamp),
                        ("dateModified", metrics.ise_tacacs_internal_user_modified_timestamp)):
                    timestamp = _timestamp(user.get(field))
                    if timestamp is not None:
                        metric.labels(username=username).set(timestamp)
                modified = _timestamp(user.get("dateModified"))
                latest_activity = max(internal_last_seen.get(username, {}).values(), default=0)
                if (enabled == "true" and modified is not None and modified < cutoff
                        and latest_activity < cutoff):
                    metrics.ise_tacacs_suspected_unused_internal_user.labels(
                        username=username,
                        reason=f"no_activity_or_change_{review_days}d").set(1)
            for object_type, count in object_counts.items():
                metrics.ise_tacacs_policy_objects_total.labels(
                    object_type=object_type).set(count)

        replace_snapshot(_CONFIG_METRICS, (publish,))


def collect_activity(dataconnect, cfg):
    with observe("tacacs_activity"):
        try:
            _collect_dataconnect(dataconnect, cfg)
            metrics.ise_tacacs_dataconnect_up.set(1)
        except Exception:
            metrics.ise_tacacs_dataconnect_up.set(0)
            raise
