"""Central metric registry and the only metric import surface for collectors."""
from prometheus_client import Gauge, Counter, Info, Enum, Histogram

from .compatibility import DEPLOYMENT_NODE_STATES

# --- availability / deployment ---
ise_exporter_build_info = Gauge(
    "ise_exporter_build_info", "Exporter package and exact ISE compatibility identity",
    ["version", "revision", "target_ise_release"])
ise_up = Gauge("ise_up", "ISE API availability (1=up, 0=down)")
ise_info = Info("ise", "ISE deployment info")
ise_deployment_status = Enum(
    "ise_deployment_status", "Status of nodes in deployment",
    labelnames=["node", "roles", "services"],
    states=DEPLOYMENT_NODE_STATES)
ise_node_count = Gauge("ise_node_count", "Number of nodes by role", ["role"])
ise_pan_ha_enabled = Gauge("ise_pan_ha_enabled", "PAN HA enabled (1=yes, 0=no)")
ise_node_service_enabled = Gauge(
    "ise_node_service_enabled", "Service currently assigned to an ISE deployment node",
    ["node", "service"])

# --- network devices ---
ise_network_devices_total = Gauge("ise_network_devices_total", "Total network devices")
ise_network_devices_by_location = Gauge("ise_network_devices_by_location", "Devices per location", ["location"])
ise_network_devices_by_ops_owner = Gauge("ise_network_devices_by_ops_owner", "Devices per ops owner", ["ops_owner"])
ise_network_devices_by_type = Gauge("ise_network_devices_by_type", "Devices by type", ["device_type"])
ise_network_device_ndg_assignment = Gauge(
    "ise_network_device_ndg_assignment",
    "Network-device assignment from normalized ISE Network Device Groups",
    ["nad", "location", "ops_owner", "device_type"])
ise_network_device_detail_coverage = Gauge(
    "ise_network_device_detail_coverage",
    "Fraction of the authoritative NAD inventory backed by cached group detail")
ise_network_device_detail_cache_entries = Gauge(
    "ise_network_device_detail_cache_entries",
    "Restart-persistent NAD group-detail rows retained by the exporter")
ise_network_device_detail_refresh_requests = Gauge(
    "ise_network_device_detail_refresh_requests",
    "NAD ERS detail requests attempted in the latest collection cycle")
ise_network_device_detail_refresh_failures = Gauge(
    "ise_network_device_detail_refresh_failures",
    "NAD ERS detail requests that failed in the latest collection cycle")
ise_network_device_detail_refresh_deferred = Gauge(
    "ise_network_device_detail_refresh_deferred",
    "Missing or stale NAD details deferred by the per-cycle request budget")
ise_nad_authentication_events = Gauge(
    "ise_nad_authentication_events",
    "Recent RADIUS authentication events attributed to configured NADs",
    ["nad", "status"])
ise_nad_last_authentication_timestamp = Gauge(
    "ise_nad_last_authentication_timestamp",
    "Most recent RADIUS authentication timestamp for each configured NAD", ["nad"])
ise_nad_seen_recently = Gauge(
    "ise_nad_seen_recently",
    "Whether a configured NAD has authentication activity in the reporting window", ["nad"])
ise_nad_unconfigured_authentication_events_topk = Gauge(
    "ise_nad_unconfigured_authentication_events_topk",
    "Recent RADIUS authentication events in the exported top-K whose NAD is not in ERS")
ise_nad_inventory_selected = Gauge(
    "ise_nad_inventory_selected",
    "Configured NADs selected for per-device health metrics")
ise_nad_inventory_total = Gauge(
    "ise_nad_inventory_total",
    "Exact configured NAD inventory size supplied by ERS")
ise_nad_inventory_truncated = Gauge(
    "ise_nad_inventory_truncated",
    "Whether configured NAD per-device health was truncated by the safety ceiling "
    "(dataconnect.max_groups no longer bounds this export)")
ise_nad_activity_groups_returned = Gauge(
    "ise_nad_activity_groups_returned",
    "NAD activity groups returned after the Data Connect top-K ceiling")
ise_nad_activity_groups_total = Gauge(
    "ise_nad_activity_groups_total",
    "Exact NAD activity group count before the Data Connect top-K ceiling")
ise_nad_activity_groups_truncated = Gauge(
    "ise_nad_activity_groups_truncated",
    "Whether NAD activity groups were truncated by the Data Connect top-K ceiling")

# --- per-NAD accumulated last-authentication (full-inventory "dead switch") ---
# ise_nad_seen_recently / ise_nad_last_authentication_timestamp above already cover
# the full configured inventory each cycle (bounded only by a safety ceiling), but
# reset to 0/absent for any NAD this cycle's Data Connect scan did not see. These
# accumulate the high-water last-authentication timestamp for every configured NAD
# ACROSS CYCLES (and restarts) in the persistent cache, so a NAD quiet for weeks
# still reports its true last-seen instead of resetting whenever the current
# cycle happens not to observe it.
ise_nad_activity_last_authentication_timestamp = Gauge(
    "ise_nad_activity_last_authentication_timestamp",
    "Accumulated most recent RADIUS authentication timestamp for each configured "
    "NAD; 0 means no authentication has ever been observed", ["nad"])
ise_nad_activity_tracked_total = Gauge(
    "ise_nad_activity_tracked_total",
    "Configured NADs with an accumulated last-authentication timestamp in the cache")
ise_nad_activity_never_authenticated_total = Gauge(
    "ise_nad_activity_never_authenticated_total",
    "Configured NADs with no RADIUS authentication ever observed by the accumulator")
ise_nad_activity_silent = Gauge(
    "ise_nad_activity_silent",
    "Configured NADs whose last observed authentication is older than the threshold",
    ["threshold_days"])
ise_nad_activity_cache_entries = Gauge(
    "ise_nad_activity_cache_entries",
    "Rows retained in the restart-persistent per-NAD activity cache")
ise_nad_activity_refresh_groups_returned = Gauge(
    "ise_nad_activity_refresh_groups_returned",
    "Recency-ranked NAD groups returned this cycle to refresh the last-authentication "
    "accumulator, bounded by the wider _LAST_SEEN_ROW_CAP ceiling")
ise_nad_activity_refresh_groups_total = Gauge(
    "ise_nad_activity_refresh_groups_total",
    "Exact NAD activity group count before the recency-ranked refresh ceiling")
ise_nad_activity_refresh_truncated = Gauge(
    "ise_nad_activity_refresh_truncated",
    "Whether the recency-ranked refresh surface was truncated by its row ceiling")

# --- certs / license / backup / patch (slow tier) ---
ise_certificate_expiry_days = Gauge("ise_certificate_expiry_days", "Days until cert expires", ["hostname", "cert_name", "cert_type", "usage"])
ise_certificates_expiring_soon = Gauge("ise_certificates_expiring_soon", "Certs expiring within threshold", ["threshold_days"])
ise_certificate_expired = Gauge("ise_certificate_expired", "Expired certificates")
ise_license_consumption = Gauge("ise_license_consumption", "License consumption", ["tier"])
ise_license_compliance = Gauge("ise_license_compliance", "License compliance", ["tier"])
ise_license_enabled = Gauge("ise_license_enabled", "License tier enabled", ["tier"])
ise_backup_last_success_timestamp = Gauge("ise_backup_last_success_timestamp", "Last successful backup ts")
ise_backup_age_hours = Gauge("ise_backup_age_hours", "Hours since last backup")
ise_backup_configured = Gauge("ise_backup_configured", "Backup configured")
ise_version_info = Info("ise_version", "ISE version information")
ise_patch_level = Gauge("ise_patch_level", "Highest installed patch number")
ise_patch_installed = Gauge("ise_patch_installed", "Patch installed", ["patch_number"])

# --- TACACS / Device Administration ---
ise_tacacs_internal_users_total = Gauge(
    "ise_tacacs_internal_users_total", "ISE internal users available to Device Administration")
ise_tacacs_internal_user_inventory_selected = Gauge(
    "ise_tacacs_internal_user_inventory_selected",
    "Internal users selected for bounded detail and hygiene collection")
ise_tacacs_internal_user_inventory_truncated = Gauge(
    "ise_tacacs_internal_user_inventory_truncated",
    "Internal users excluded by the configured detail inventory ceiling")
ise_tacacs_internal_user_detail_coverage = Gauge(
    "ise_tacacs_internal_user_detail_coverage",
    "Fraction of the complete enumerated internal-user inventory backed by cached ERS detail")
ise_tacacs_internal_user_detail_cache_entries = Gauge(
    "ise_tacacs_internal_user_detail_cache_entries",
    "Restart-persistent internal-user detail rows retained by the exporter")
ise_tacacs_internal_user_detail_refresh_requests = Gauge(
    "ise_tacacs_internal_user_detail_refresh_requests",
    "Internal-user ERS detail requests attempted in the latest collection cycle")
ise_tacacs_internal_user_detail_refresh_failures = Gauge(
    "ise_tacacs_internal_user_detail_refresh_failures",
    "Internal-user ERS detail requests that failed in the latest collection cycle")
ise_tacacs_internal_user_detail_refresh_deferred = Gauge(
    "ise_tacacs_internal_user_detail_refresh_deferred",
    "Missing or stale internal-user details deferred by the per-cycle request budget")
ise_tacacs_internal_user_info = Gauge(
    "ise_tacacs_internal_user_info", "ISE internal-user account state",
    ["username", "enabled", "password_never_expires", "change_password", "identity_store"])
ise_tacacs_internal_user_created_timestamp = Gauge(
    "ise_tacacs_internal_user_created_timestamp", "Internal-user creation timestamp",
    ["username"])
ise_tacacs_internal_user_modified_timestamp = Gauge(
    "ise_tacacs_internal_user_modified_timestamp", "Internal-user last-modified timestamp",
    ["username"])
ise_tacacs_suspected_unused_internal_user = Gauge(
    "ise_tacacs_suspected_unused_internal_user",
    "Internal-user candidate for review based on account age and observed TACACS activity",
    ["username", "reason"])
ise_tacacs_unused_account_review_seconds = Gauge(
    "ise_tacacs_unused_account_review_seconds",
    "Configured inactivity period before an internal TACACS account is reviewed")
ise_tacacs_internal_user_hygiene_risk = Gauge(
    "ise_tacacs_internal_user_hygiene_risk", "Internal-user account hygiene review finding",
    ["username", "risk"])
ise_tacacs_policy_objects_total = Gauge(
    "ise_tacacs_policy_objects_total", "Configured Device Admin objects by type",
    ["object_type"])
ise_tacacs_policy_set_inventory_selected = Gauge(
    "ise_tacacs_policy_set_inventory_selected",
    "Device Admin policy sets selected for bounded rule-count collection")
ise_tacacs_policy_set_inventory_truncated = Gauge(
    "ise_tacacs_policy_set_inventory_truncated",
    "Device Admin policy sets excluded by the configured cache ceiling")
ise_tacacs_policy_rule_coverage = Gauge(
    "ise_tacacs_policy_rule_coverage",
    "Fraction of the complete policy-set inventory backed by cached rule counts")
ise_tacacs_policy_rule_cache_entries = Gauge(
    "ise_tacacs_policy_rule_cache_entries",
    "Restart-persistent complete Device Admin policy rule-count rows")
ise_tacacs_policy_rule_refresh_requests = Gauge(
    "ise_tacacs_policy_rule_refresh_requests",
    "Policy sets whose authentication and authorization rules were requested this cycle")
ise_tacacs_policy_rule_refresh_failures = Gauge(
    "ise_tacacs_policy_rule_refresh_failures",
    "Policy-set rule-count refreshes that failed this cycle")
ise_tacacs_policy_rule_refresh_deferred = Gauge(
    "ise_tacacs_policy_rule_refresh_deferred",
    "Missing or stale policy-set rule counts deferred by the cycle budget")
ise_tacacs_dataconnect_up = Gauge(
    "ise_tacacs_dataconnect_up", "ISE Data Connect TACACS query status (1=successful)")
ise_tacacs_account_authentication_events = Gauge(
    "ise_tacacs_account_authentication_events",
    "TACACS authentication events in the configured bounded reporting window",
    ["username", "status", "device", "policy", "identity_store", "failure_class"])
ise_tacacs_account_authorization_events = Gauge(
    "ise_tacacs_account_authorization_events",
    "TACACS authorization events in the configured bounded reporting window",
    ["username", "status", "device", "policy", "shell_profile", "command_set"])
ise_tacacs_accounting_events = Gauge(
    "ise_tacacs_accounting_events",
    "TACACS accounting events in the configured bounded reporting window",
    ["username", "status", "device", "command_family"])
ise_tacacs_account_last_seen_timestamp = Gauge(
    "ise_tacacs_account_last_seen_timestamp",
    "Most recent TACACS event timestamp observed through Data Connect; internal-account high-water values persist across view rollover",
    ["username", "event_type"])
ise_tacacs_events_total = Gauge(
    "ise_tacacs_events_total", "Exact TACACS events in each configured reporting window",
    ["event_type"])
ise_tacacs_topk_groups_returned = Gauge(
    "ise_tacacs_topk_groups_returned", "TACACS groups exported after the top-K limit",
    ["event_type"])
ise_tacacs_topk_groups_total = Gauge(
    "ise_tacacs_topk_groups_total", "Exact TACACS groups before the top-K limit",
    ["event_type"])
ise_tacacs_topk_truncated = Gauge(
    "ise_tacacs_topk_truncated", "Whether TACACS groups were truncated by the top-K limit",
    ["event_type"])

# --- MnT bounded active-session posture plane ---
# These are current, bounded samples from MnT Session detail. They intentionally
# do not populate Data Connect's historical posture metric families.
ise_mnt_session_list_preflight_count = Gauge(
    "ise_mnt_session_list_preflight_count",
    "Active sessions reported by the bounded MnT ActiveCount preflight")
ise_mnt_session_list_ceiling = Gauge(
    "ise_mnt_session_list_ceiling",
    "Maximum ActiveCount permitted before the unpaged MnT ActiveList is refused")
ise_mnt_session_list_skipped = Gauge(
    "ise_mnt_session_list_skipped",
    "Whether MnT ActiveList was refused because ActiveCount exceeded its ceiling")
ise_mnt_active_sessions_total = Gauge(
    "ise_mnt_active_sessions_total", "Active sessions reported by the MnT ActiveList")
ise_mnt_active_posture_candidate_endpoints_total = Gauge(
    "ise_mnt_active_posture_candidate_endpoints_total",
    "Unique valid active MAC addresses eligible for bounded MnT detail lookup")
ise_mnt_active_posture_detail_requests = Gauge(
    "ise_mnt_active_posture_detail_requests",
    "Unique active endpoints selected for bounded MnT detail lookup")
ise_mnt_active_posture_detail_endpoints = Gauge(
    "ise_mnt_active_posture_detail_endpoints",
    "Selected active endpoints whose MnT session detail was collected")
ise_mnt_active_posture_detail_coverage_ratio = Gauge(
    "ise_mnt_active_posture_detail_coverage_ratio",
    "Successful MnT session-detail lookups divided by selected endpoints")
ise_mnt_active_posture_detail_truncated = Gauge(
    "ise_mnt_active_posture_detail_truncated",
    "Whether active endpoint detail lookup was limited by the configured bound")
ise_mnt_active_posture_cache_entries = Gauge(
    "ise_mnt_active_posture_cache_entries",
    "Active endpoint details retained in the restart-persistent MnT cache")
ise_mnt_active_posture_cache_hits = Gauge(
    "ise_mnt_active_posture_cache_hits",
    "Active endpoint details served from the persistent cache in the latest cycle")
ise_mnt_active_posture_cache_misses = Gauge(
    "ise_mnt_active_posture_cache_misses",
    "Selected active endpoints without a cached detail in the latest cycle")
ise_mnt_active_posture_refresh_deferred = Gauge(
    "ise_mnt_active_posture_refresh_deferred",
    "Endpoint detail refreshes deferred by the per-cycle request budget")
ise_mnt_active_posture_cache_oldest_age_seconds = Gauge(
    "ise_mnt_active_posture_cache_oldest_age_seconds",
    "Age of the oldest cached active endpoint detail used in the current snapshot")
ise_mnt_active_posture_field_coverage_ratio = Gauge(
    "ise_mnt_active_posture_field_coverage_ratio",
    "Fraction of collected MnT details containing a useful source field", ["field"])
ise_mnt_active_posture_endpoints = Gauge(
    "ise_mnt_active_posture_endpoints",
    "Collected active endpoints grouped by current MnT posture status, agent OS, and PSN",
    ["status", "os", "psn"])
ise_mnt_active_secure_client_endpoints = Gauge(
    "ise_mnt_active_secure_client_endpoints",
    "Collected active endpoints grouped by normalized Secure Client posture-agent version",
    ["agent_version"])
ise_mnt_active_posture_policy_results = Gauge(
    "ise_mnt_active_posture_policy_results",
    "Posture policy rollups parsed from collected active endpoint PostureReport fields",
    ["policy", "result"])
ise_mnt_active_step_latency_seconds = Gauge(
    "ise_mnt_active_step_latency_seconds",
    "Bounded MnT active-session step latency aggregate by numeric ISE step code",
    ["step", "stat"])
ise_mnt_active_step_latency_samples = Gauge(
    "ise_mnt_active_step_latency_samples",
    "Number of valid bounded MnT latency samples by numeric ISE step code", ["step"])
ise_mnt_active_total_authentication_latency_seconds = Gauge(
    "ise_mnt_active_total_authentication_latency_seconds",
    "Bounded MnT active-session TotalAuthenLatency aggregate", ["stat"])
ise_mnt_active_total_authentication_latency_samples = Gauge(
    "ise_mnt_active_total_authentication_latency_samples",
    "Number of valid bounded MnT TotalAuthenLatency samples")

# --- Data Connect reporting plane ---
# These metrics are populated only by the Data Connect domain collectors.  REST
# and legacy MnT collectors must not write them, which keeps ownership and
# snapshot semantics explicit.
ise_dataconnect_radius_authentication_events = Gauge(
    "ise_dataconnect_radius_authentication_events",
    "RADIUS authentication events in the bounded Data Connect reporting window",
    ["status", "authentication_method", "authentication_protocol", "nad",
     "authorization_policy", "psn"])
ise_dataconnect_radius_authentication_events_total = Gauge(
    "ise_dataconnect_radius_authentication_events_total",
    "Exact RADIUS authentication event count in the Data Connect reporting window")
ise_dataconnect_radius_distinct_endpoints_total = Gauge(
    "ise_dataconnect_radius_distinct_endpoints_total",
    "Exact distinct calling-station identifiers in the RADIUS reporting window",
    ["source_view"])
ise_dataconnect_radius_failure_events = Gauge(
    "ise_dataconnect_radius_failure_events",
    "Failed RADIUS authentications by bounded reason class, authorization profile, and location",
    ["failure_class", "authorization_profile", "location"])
ise_dataconnect_radius_failure_events_total = Gauge(
    "ise_dataconnect_radius_failure_events_total",
    "Exact failed RADIUS authentication count in the Data Connect reporting window")
ise_dataconnect_radius_authentication_summary_events = Gauge(
    "ise_dataconnect_radius_authentication_summary_events",
    "RADIUS authentication summary events by bounded documented reporting dimension",
    ["dimension", "value", "status"])
ise_dataconnect_radius_response_time_seconds = Gauge(
    "ise_dataconnect_radius_response_time_seconds",
    "RADIUS response-time aggregate from Data Connect",
    ["stat", "status", "nad", "psn"])
ise_dataconnect_radius_response_time_samples = Gauge(
    "ise_dataconnect_radius_response_time_samples",
    "RADIUS events with a non-null response time in Data Connect",
    ["status", "nad", "psn"])
ise_dataconnect_radius_accounting_events = Gauge(
    "ise_dataconnect_radius_accounting_events",
    "RADIUS accounting events in the bounded Data Connect reporting window",
    ["event_type", "nad", "authorization_policy", "psn"])
ise_dataconnect_radius_accounting_events_total = Gauge(
    "ise_dataconnect_radius_accounting_events_total",
    "Exact RADIUS accounting event count in the Data Connect reporting window")
ise_dataconnect_radius_accounting_event_type_total = Gauge(
    "ise_dataconnect_radius_accounting_event_type_total",
    "Exact RADIUS accounting event count for normalized start and stop event classes",
    ["event_type"])
ise_dataconnect_radius_accounting_session_seconds = Gauge(
    "ise_dataconnect_radius_accounting_session_seconds",
    "RADIUS accounting session-time aggregate from Data Connect",
    ["stat", "nad", "psn"])

# --- incremental accounting-event counters (opt-in; incremental tailing Slice 1) ---
# Monotonic counters accumulated by tailing only new RADIUS_ACCOUNTING rows since a
# persisted id cursor, so Prometheus owns the windowing (rate()/increase()) instead
# of the exporter re-summing a fixed server-side window each cycle. Low-cardinality
# by design (event_type x psn); per-NAD breakdowns stay on the windowed top-K gauges.
# Off unless dataconnect.accounting_event_counters is enabled.
ise_dataconnect_radius_accounting_tail_total = Counter(
    "ise_dataconnect_radius_accounting_tail_total",
    "RADIUS accounting events observed by incremental id-tailing since exporter start",
    ["event_type", "psn"])
ise_dataconnect_posture_assessment_tail_total = Counter(
    "ise_dataconnect_posture_assessment_tail_total",
    "Posture assessment events observed by incremental id-tailing since exporter start",
    ["status", "psn"])
ise_dataconnect_radius_authentication_tail_total = Counter(
    "ise_dataconnect_radius_authentication_tail_total",
    "RADIUS authentication events observed by incremental id-tailing since exporter start",
    ["result", "psn"])
ise_dataconnect_radius_error_tail_total = Counter(
    "ise_dataconnect_radius_error_tail_total",
    "RADIUS error events observed by incremental id-tailing since exporter start",
    ["message_code", "psn"])
ise_dataconnect_tail_cursor_id = Gauge(
    "ise_dataconnect_tail_cursor_id",
    "Last incremental-tail high-water id committed for a Data Connect view", ["view"])
ise_dataconnect_tail_events_last_cycle = Gauge(
    "ise_dataconnect_tail_events_last_cycle",
    "Rows folded into counters by the last incremental-tail cycle for a view", ["view"])
ise_dataconnect_tail_resets_total = Counter(
    "ise_dataconnect_tail_resets_total",
    "Times an incremental-tail cursor was re-seeded after a backward id jump (sequence reset)",
    ["view"])
ise_dataconnect_radius_active_sessions = Gauge(
    "ise_dataconnect_radius_active_sessions",
    "Likely active sessions whose latest accounting record is non-stop and within the stale cutoff",
    ["nad", "psn"])
ise_dataconnect_radius_active_sessions_total = Gauge(
    "ise_dataconnect_radius_active_sessions_total",
    "Exact accounting-derived likely-active session count before top-K breakdown limiting")
ise_dataconnect_radius_active_session_stale_cutoff_seconds = Gauge(
    "ise_dataconnect_radius_active_session_stale_cutoff_seconds",
    "Maximum age of the latest non-stop accounting record counted as likely active")
ise_dataconnect_radius_active_groups_returned = Gauge(
    "ise_dataconnect_radius_active_groups_returned",
    "Number of NAD and PSN active-session groups exported after the top-K limit")
ise_dataconnect_radius_active_groups_total = Gauge(
    "ise_dataconnect_radius_active_groups_total",
    "Exact number of NAD and PSN active-session groups before the top-K limit")
ise_dataconnect_radius_active_groups_truncated = Gauge(
    "ise_dataconnect_radius_active_groups_truncated",
    "Whether the active-session NAD and PSN breakdown was truncated")
ise_dataconnect_radius_errors = Gauge(
    "ise_dataconnect_radius_errors",
    "RADIUS errors grouped by stable troubleshooting dimensions",
    ["message_code", "message_text", "nad", "authentication_method", "psn"])
ise_dataconnect_radius_errors_total = Gauge(
    "ise_dataconnect_radius_errors_total",
    "Exact RADIUS error count in the Data Connect reporting window")
ise_dataconnect_radius_topk_groups_returned = Gauge(
    "ise_dataconnect_radius_topk_groups_returned",
    "Number of dimensional groups exported after the Data Connect top-K limit",
    ["breakdown"])
ise_dataconnect_radius_topk_groups_total = Gauge(
    "ise_dataconnect_radius_topk_groups_total",
    "Dimensional group count before the top-K limit; a lower bound when exactness is zero",
    ["breakdown"])
ise_dataconnect_radius_topk_groups_total_exact = Gauge(
    "ise_dataconnect_radius_topk_groups_total_exact",
    "Whether the reported RADIUS dimensional group count is exact",
    ["breakdown"])
ise_dataconnect_radius_topk_truncated = Gauge(
    "ise_dataconnect_radius_topk_truncated",
    "Whether a RADIUS dimensional breakdown was truncated by its top-K limit",
    ["breakdown"])

ise_dataconnect_posture_endpoint_assessments = Gauge(
    "ise_dataconnect_posture_endpoint_assessments",
    "Distinct endpoints assessed by posture status, OS, agent, policy, and PSN",
    ["status", "os", "agent_version", "policy", "psn"])
ise_dataconnect_posture_assessed_endpoints_total = Gauge(
    "ise_dataconnect_posture_assessed_endpoints_total",
    "Exact distinct endpoints represented by their latest posture assessment")
ise_dataconnect_posture_eligible_endpoints_total = Gauge(
    "ise_dataconnect_posture_eligible_endpoints_total",
    "Endpoint reporting-snapshot rows marked posture-applicable", ["source_view"])
ise_dataconnect_posture_eligible_recently_assessed_total = Gauge(
    "ise_dataconnect_posture_eligible_recently_assessed_total",
    "Posture-applicable endpoints with an assessment in the configured reporting window",
    ["source_view"])
ise_dataconnect_posture_eligible_without_recent_assessment_total = Gauge(
    "ise_dataconnect_posture_eligible_without_recent_assessment_total",
    "Posture-applicable endpoints without an assessment in the configured reporting window",
    ["source_view"])
ise_dataconnect_posture_eligible_recent_assessment_ratio = Gauge(
    "ise_dataconnect_posture_eligible_recent_assessment_ratio",
    "Fraction of posture-applicable endpoints assessed in the configured reporting window",
    ["source_view"])
ise_dataconnect_posture_compliant_endpoints_total = Gauge(
    "ise_dataconnect_posture_compliant_endpoints_total",
    "Exact endpoints whose latest posture assessment is compliant")
ise_dataconnect_posture_failed_endpoints_total = Gauge(
    "ise_dataconnect_posture_failed_endpoints_total",
    "Exact endpoints whose latest posture assessment is an explicit failure state")
ise_dataconnect_posture_compliance_ratio = Gauge(
    "ise_dataconnect_posture_compliance_ratio",
    "Compliant fraction of latest explicit compliant-or-failed posture assessments")
ise_dataconnect_posture_condition_assessments = Gauge(
    "ise_dataconnect_posture_condition_assessments",
    "Distinct endpoints assessed by posture policy condition and result",
    ["policy", "policy_status", "condition", "condition_status", "enforcement"])
ise_dataconnect_posture_enforcement_assessments = Gauge(
    "ise_dataconnect_posture_enforcement_assessments",
    "Distinct posture endpoints by enforcement result and ISE node",
    ["enforcement", "enforcement_type", "enforcement_status", "posture_status", "psn"])
ise_dataconnect_posture_failures = Gauge(
    "ise_dataconnect_posture_failures",
    "Distinct failed posture endpoints grouped by message code and policy",
    ["message_code", "status", "policy", "psn"])
ise_dataconnect_posture_topk_groups_returned = Gauge(
    "ise_dataconnect_posture_topk_groups_returned",
    "Number of posture dimensional groups exported after the Data Connect top-K limit",
    ["breakdown"])
ise_dataconnect_posture_topk_groups_total = Gauge(
    "ise_dataconnect_posture_topk_groups_total",
    "Exact number of posture dimensional groups before the Data Connect top-K limit",
    ["breakdown"])
ise_dataconnect_posture_topk_truncated = Gauge(
    "ise_dataconnect_posture_topk_truncated",
    "Whether a posture dimensional breakdown was truncated by its top-K limit",
    ["breakdown"])

# --- endpoint fleet: accumulated per-endpoint latest posture (opt-in) ---
# Aggregates over a restart-persistent cache that keeps each endpoint's latest
# posture assessment across cycles. Coverage accumulates toward the full
# posture-applicable population over days instead of resetting to one bounded
# reporting window. Disabled by default; enabled with endpoint_fleet.enabled.
ise_endpoint_fleet_assessed_total = Gauge(
    "ise_endpoint_fleet_assessed_total",
    "Distinct endpoints with an accumulated latest posture assessment in the fleet cache")
ise_endpoint_fleet_eligible_total = Gauge(
    "ise_endpoint_fleet_eligible_total",
    "Posture-applicable endpoints in the reporting inventory used as the coverage denominator")
ise_endpoint_fleet_coverage_ratio = Gauge(
    "ise_endpoint_fleet_coverage_ratio",
    "Accumulated assessed endpoints divided by posture-applicable endpoints")
ise_endpoint_fleet_compliance_ratio = Gauge(
    "ise_endpoint_fleet_compliance_ratio",
    "Compliant fraction of accumulated endpoints in an explicit compliant-or-failed state")
ise_endpoint_fleet_posture = Gauge(
    "ise_endpoint_fleet_posture",
    "Accumulated endpoints by latest posture status", ["status"])
ise_endpoint_fleet_by_os = Gauge(
    "ise_endpoint_fleet_by_os",
    "Accumulated endpoints by latest reported operating system", ["os"])
ise_endpoint_fleet_by_agent_version = Gauge(
    "ise_endpoint_fleet_by_agent_version",
    "Accumulated endpoints by latest Secure Client posture-agent version", ["agent_version"])
ise_endpoint_fleet_by_policy = Gauge(
    "ise_endpoint_fleet_by_policy",
    "Accumulated endpoints by latest matched posture policy", ["policy"])
ise_endpoint_fleet_by_psn = Gauge(
    "ise_endpoint_fleet_by_psn",
    "Accumulated endpoints by latest assessing ISE node", ["psn"])
ise_endpoint_fleet_cache_entries = Gauge(
    "ise_endpoint_fleet_cache_entries",
    "Rows retained in the restart-persistent endpoint fleet cache")
ise_endpoint_fleet_oldest_assessment_age_seconds = Gauge(
    "ise_endpoint_fleet_oldest_assessment_age_seconds",
    "Age of the oldest accumulated posture assessment still retained in the fleet cache")
ise_endpoint_fleet_stale = Gauge(
    "ise_endpoint_fleet_stale",
    "Accumulated endpoints whose latest posture assessment is older than the age threshold",
    ["age_days"])
ise_endpoint_fleet_scan_truncated = Gauge(
    "ise_endpoint_fleet_scan_truncated",
    "Whether one accumulation scan hit its row cap and may have dropped re-postures "
    "(raise endpoint_fleet.max_rows if this stays 1)")

ise_dataconnect_endpoints_total = Gauge(
    "ise_dataconnect_endpoints_total",
    "Endpoints in the Data Connect reporting inventory snapshot")
ise_dataconnect_endpoints_unknown_profile_total = Gauge(
    "ise_dataconnect_endpoints_unknown_profile_total",
    "Endpoint snapshot count with a missing or unknown endpoint policy", ["source_view"])
ise_dataconnect_endpoint_field_populated = Gauge(
    "ise_dataconnect_endpoint_field_populated",
    "Endpoint snapshot rows with a populated operational inventory field", ["field"])
ise_dataconnect_endpoint_field_coverage_ratio = Gauge(
    "ise_dataconnect_endpoint_field_coverage_ratio",
    "Fraction of endpoint snapshot rows with a populated operational inventory field", ["field"])
ise_dataconnect_endpoints_stale = Gauge(
    "ise_dataconnect_endpoints_stale",
    "Endpoint snapshot rows not updated within the configured age threshold", ["age_days"])
ise_dataconnect_profiled_endpoint_group_memberships_total = Gauge(
    "ise_dataconnect_profiled_endpoint_group_memberships_total",
    "Exact sum of distinct endpoint memberships across profiling groups in the reporting window")
ise_dataconnect_endpoints_by_profile = Gauge(
    "ise_dataconnect_endpoints_by_profile", "Endpoint snapshot rows by endpoint policy",
    ["profile"])
ise_dataconnect_endpoints_by_posture_applicable = Gauge(
    "ise_dataconnect_endpoints_by_posture_applicable",
    "Endpoint snapshot rows by posture-applicable state", ["applicable"])
ise_dataconnect_profile_events = Gauge(
    "ise_dataconnect_profile_events",
    "Distinct profiled endpoints in the bounded Data Connect reporting window",
    ["profile", "source", "action", "identity_group"])
ise_dataconnect_endpoint_topk_groups_returned = Gauge(
    "ise_dataconnect_endpoint_topk_groups_returned",
    "Number of endpoint dimensional groups exported after the Data Connect top-K limit",
    ["breakdown"])
ise_dataconnect_endpoint_topk_groups_total = Gauge(
    "ise_dataconnect_endpoint_topk_groups_total",
    "Exact number of endpoint dimensional groups before the Data Connect top-K limit",
    ["breakdown"])
ise_dataconnect_endpoint_topk_truncated = Gauge(
    "ise_dataconnect_endpoint_topk_truncated",
    "Whether an endpoint dimensional breakdown was truncated by its top-K limit",
    ["breakdown"])

ise_dataconnect_view_has_recent_rows = Gauge(
    "ise_dataconnect_view_has_recent_rows",
    "Whether each Data Connect reporting view contains a row in the bounded recent window",
    ["view", "domain"])
ise_dataconnect_view_newest_recent_event_timestamp = Gauge(
    "ise_dataconnect_view_newest_recent_event_timestamp",
    "Newest source-event timestamp inside each Data Connect view's bounded recent window",
    ["view", "domain"])
ise_dataconnect_view_freshness_expected = Gauge(
    "ise_dataconnect_view_freshness_expected",
    "Whether recent rows are expected for health evaluation rather than activity-only",
    ["view", "domain"])
ise_dataconnect_psn_radius_requests_per_hour = Gauge(
    "ise_dataconnect_psn_radius_requests_per_hour", "RADIUS requests per hour by ISE node",
    ["node"])
ise_dataconnect_psn_mnt_logs_per_hour = Gauge(
    "ise_dataconnect_psn_mnt_logs_per_hour", "Messages logged to MnT per hour by ISE node",
    ["node"])
ise_dataconnect_psn_noise_per_hour = Gauge(
    "ise_dataconnect_psn_noise_per_hour", "Noise messages per hour by ISE node", ["node"])
ise_dataconnect_psn_suppression_per_hour = Gauge(
    "ise_dataconnect_psn_suppression_per_hour", "Suppressed messages per hour by ISE node",
    ["node"])
ise_dataconnect_psn_load_percent = Gauge(
    "ise_dataconnect_psn_load_percent", "ISE node load percentage", ["node", "stat"])
ise_dataconnect_psn_average_latency_seconds = Gauge(
    "ise_dataconnect_psn_average_latency_seconds",
    "Average RADIUS request latency by ISE node", ["node"])
ise_dataconnect_psn_average_tps = Gauge(
    "ise_dataconnect_psn_average_tps", "Average transactions per second by ISE node", ["node"])
ise_dataconnect_node_cpu_utilization_percent = Gauge(
    "ise_dataconnect_node_cpu_utilization_percent", "CPU utilization percentage by ISE node",
    ["node"])
ise_dataconnect_node_memory_utilization_percent = Gauge(
    "ise_dataconnect_node_memory_utilization_percent", "Memory utilization percentage by ISE node",
    ["node"])
ise_dataconnect_node_disk_utilization_percent = Gauge(
    "ise_dataconnect_node_disk_utilization_percent", "Disk utilization percentage by node and partition",
    ["node", "partition"])
ise_dataconnect_diagnostic_events = Gauge(
    "ise_dataconnect_diagnostic_events",
    "Diagnostic events in the bounded Data Connect reporting window",
    ["source", "node", "severity", "category", "message_code"])
ise_dataconnect_diagnostic_events_total = Gauge(
    "ise_dataconnect_diagnostic_events_total",
    "Exact diagnostic event total before the Data Connect top-K limit", ["source"])
ise_dataconnect_diagnostic_topk_groups_returned = Gauge(
    "ise_dataconnect_diagnostic_topk_groups_returned",
    "Number of diagnostic groups exported after the Data Connect top-K limit", ["source"])
ise_dataconnect_diagnostic_topk_groups_total = Gauge(
    "ise_dataconnect_diagnostic_topk_groups_total",
    "Exact number of diagnostic groups before the Data Connect top-K limit", ["source"])
ise_dataconnect_diagnostic_topk_truncated = Gauge(
    "ise_dataconnect_diagnostic_topk_truncated",
    "Whether a diagnostic breakdown was truncated by its Data Connect top-K limit",
    ["source"])

# --- exporter self-observability ---
ise_dataconnect_schema_column_available = Gauge(
    "ise_dataconnect_schema_column_available",
    "Whether a known Data Connect reporting column is present in the discovered schema",
    ["view", "column", "requirement"])
ise_dataconnect_schema_optional_columns_missing = Gauge(
    "ise_dataconnect_schema_optional_columns_missing",
    "Known optional Data Connect columns absent from available reporting views")
ise_dataconnect_schema_view_available = Gauge(
    "ise_dataconnect_schema_view_available",
    "Whether a known Data Connect reporting view is present in the discovered schema",
    ["view", "requirement"])
ise_dataset_up = Gauge(
    "ise_dataset_up", "Authoritative dataset collection status (1=successful)",
    ["dataset", "source"])
ise_dataset_enabled = Gauge(
    "ise_dataset_enabled", "Whether the dataset is enabled by the immutable collection plan",
    ["dataset", "source"])
ise_dataset_interval_seconds = Gauge(
    "ise_dataset_interval_seconds", "Configured successful collection cadence",
    ["dataset", "source"])
ise_dataset_fresh = Gauge(
    "ise_dataset_fresh",
    "Whether the last successful replacement is within two configured collection intervals",
    ["dataset", "source"])
ise_dataset_last_attempt_timestamp = Gauge(
    "ise_dataset_last_attempt_timestamp", "Last attempted authoritative dataset collection",
    ["dataset", "source"])
ise_dataset_last_success_timestamp = Gauge(
    "ise_dataset_last_success_timestamp",
    "Last successful authoritative dataset replacement", ["dataset", "source"])
ise_dataset_last_failure_info = Gauge(
    "ise_dataset_last_failure_info",
    "Latest authoritative dataset failure category (removed after recovery)",
    ["dataset", "source", "reason"])
ise_dataset_last_failure_detail_info = Gauge(
    "ise_dataset_last_failure_detail_info",
    "Latest bounded authoritative dataset failure explanation (removed after recovery)",
    ["dataset", "source", "reason", "detail"])
ise_scrape_duration_seconds = Histogram("ise_scrape_duration_seconds", "Scrape time", buckets=[1, 5, 10, 30, 60, 120, 300])
ise_scrape_errors_total = Counter("ise_scrape_errors_total", "Scrape errors", ["collector", "error_type"])
ise_api_requests_total = Counter("ise_api_requests_total", "API requests", ["api", "status"])
ise_api_errors_total = Counter("ise_api_errors_total", "API errors", ["api", "error_type", "http_code"])
ise_collector_duration_seconds = Gauge("ise_collector_duration_seconds", "Per-collector duration", ["collector"])
ise_last_successful_scrape = Gauge("ise_last_successful_scrape_timestamp", "Last success ts", ["collector"])
ise_consecutive_failures = Gauge("ise_consecutive_failures", "Consecutive failures", ["collector"])
ise_collector_enabled = Gauge("ise_collector_enabled", "Collector enabled", ["collector"])
ise_dataconnect_queries_total = Counter(
    "ise_dataconnect_queries_total",
    "Data Connect statements by fixed reporting view and result", ["view", "result"])
ise_dataconnect_query_duration_seconds = Histogram(
    "ise_dataconnect_query_duration_seconds",
    "Data Connect statement duration by fixed reporting view and result",
    ["view", "result"], buckets=[0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 30])
ise_dataconnect_query_last_duration_seconds = Gauge(
    "ise_dataconnect_query_last_duration_seconds",
    "Duration of the latest completed Data Connect statement",
    ["view", "result"])
ise_dataconnect_query_rows = Gauge(
    "ise_dataconnect_query_rows",
    "Rows returned by the latest Data Connect statement for a fixed reporting view",
    ["view"])
ise_dataconnect_query_pacing_seconds = Gauge(
    "ise_dataconnect_query_pacing_seconds",
    "Configured minimum idle time between Data Connect statements")
ise_dataconnect_max_duty_cycle_percent = Gauge(
    "ise_dataconnect_max_duty_cycle_percent",
    "Configured hard maximum Data Connect reporting-query duty cycle in percent")
ise_dataconnect_duty_cycle_recommended_min_percent = Gauge(
    "ise_dataconnect_duty_cycle_recommended_min_percent",
    "Lower bound of the recommended Data Connect duty-cycle band; below this the "
    "global cooldown throttles operational datasets far below their configured cadence")
ise_dataconnect_duty_cycle_recommended_max_percent = Gauge(
    "ise_dataconnect_duty_cycle_recommended_max_percent",
    "Upper bound of the recommended Data Connect duty-cycle band; above this the "
    "sustained reporting load on the ISE database becomes significant")
ise_dataconnect_duty_cycle_advisory = Gauge(
    "ise_dataconnect_duty_cycle_advisory",
    "Configured duty cycle vs the recommended band: -1 below, 0 within, 1 above")
ise_dataconnect_query_timeout_seconds = Gauge(
    "ise_dataconnect_query_timeout_seconds",
    "Hard total timeout for one Data Connect query attempt")
ise_dataconnect_result_row_ceiling = Gauge(
    "ise_dataconnect_result_row_ceiling",
    "Hard maximum rows retained from one Data Connect statement")
ise_dataconnect_result_byte_ceiling = Gauge(
    "ise_dataconnect_result_byte_ceiling",
    "Hard maximum materialized bytes retained from one Data Connect statement or batch")
ise_dataconnect_scan_window_hours = Gauge(
    "ise_dataconnect_scan_window_hours",
    "Scheduled event-history scan window after applying the production ceiling",
    ["dataset"])
ise_dataconnect_query_cooldown_seconds = Gauge(
    "ise_dataconnect_query_cooldown_seconds",
    "Latest global duty-cycle cooldown after a Data Connect statement", ["view"])
ise_dataconnect_worker_busy = Gauge(
    "ise_dataconnect_worker_busy",
    "Whether the serialized Data Connect collection worker is executing a domain")
ise_dataconnect_queue_depth = Gauge(
    "ise_dataconnect_queue_depth",
    "Number of Data Connect domains queued behind the serialized worker")
ise_dataconnect_oldest_queued_seconds = Gauge(
    "ise_dataconnect_oldest_queued_seconds",
    "Age of the oldest Data Connect domain waiting for the serialized worker")
ise_mnt_worker_busy = Gauge(
    "ise_mnt_worker_busy",
    "Whether the bounded MnT active-posture worker is executing")
ise_dataset_effective_interval_seconds = Gauge(
    "ise_dataset_effective_interval_seconds",
    "Scheduled collection cadence currently applied by the scheduler", ["dataset", "source"])
