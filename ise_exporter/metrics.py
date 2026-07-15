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
ise_nad_unconfigured_authentication_events_total = Gauge(
    "ise_nad_unconfigured_authentication_events_total",
    "Recent RADIUS authentication events whose NAD name is not configured in ERS")

# --- certs / license / backup / patch (slow tier) ---
ise_certificate_expiry_days = Gauge("ise_certificate_expiry_days", "Days until cert expires", ["hostname", "cert_name", "cert_type", "usage"])
ise_certificates_expiring_soon = Gauge("ise_certificates_expiring_soon", "Certs expiring within threshold", ["threshold_days"])
ise_certificate_expired = Gauge("ise_certificate_expired", "Expired certificates")
ise_certificate_key_size_bits = Gauge(
    "ise_certificate_key_size_bits", "Certificate public-key size",
    ["hostname", "cert_name", "cert_type"])
ise_certificate_weak_signature = Gauge(
    "ise_certificate_weak_signature", "Certificate uses a deprecated signature algorithm",
    ["hostname", "cert_name", "cert_type"])
ise_certificate_self_signed = Gauge(
    "ise_certificate_self_signed", "System certificate is self-signed",
    ["hostname", "cert_name"])
ise_certificate_binding = Gauge(
    "ise_certificate_binding", "Certificate service/trust binding by canonical role",
    ["hostname", "cert_name", "cert_type", "role"])
ise_certificate_issuer_present_in_trust_store = Gauge(
    "ise_certificate_issuer_present_in_trust_store",
    "System certificate issuer matches a subject in the ISE trusted-certificate store",
    ["hostname", "cert_name"])
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
ise_mnt_active_posture_applicable_endpoints = Gauge(
    "ise_mnt_active_posture_applicable_endpoints",
    "Collected active endpoints grouped by posture-applicable state", ["applicable"])
ise_mnt_active_posture_assessment_endpoints = Gauge(
    "ise_mnt_active_posture_assessment_endpoints",
    "Collected active endpoints grouped by current posture assessment status", ["status"])
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
    "Exact distinct calling-station identifiers in the RADIUS reporting window")
ise_dataconnect_radius_distinct_users_total = Gauge(
    "ise_dataconnect_radius_distinct_users_total",
    "Exact distinct usernames in the RADIUS reporting window")
ise_dataconnect_radius_failure_events = Gauge(
    "ise_dataconnect_radius_failure_events",
    "Failed RADIUS authentications by bounded reason class, authorization profile, and location",
    ["failure_class", "authorization_profile", "location"])
ise_dataconnect_radius_failure_events_total = Gauge(
    "ise_dataconnect_radius_failure_events_total",
    "Exact failed RADIUS authentication count in the Data Connect reporting window")
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
    ["message_code", "nad", "authentication_method", "psn"])
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
    "Current endpoints marked posture-applicable in endpoint inventory")
ise_dataconnect_posture_eligible_recently_assessed_total = Gauge(
    "ise_dataconnect_posture_eligible_recently_assessed_total",
    "Posture-applicable endpoints with an assessment in the configured reporting window")
ise_dataconnect_posture_eligible_without_recent_assessment_total = Gauge(
    "ise_dataconnect_posture_eligible_without_recent_assessment_total",
    "Posture-applicable endpoints without an assessment in the configured reporting window")
ise_dataconnect_posture_eligible_recent_assessment_ratio = Gauge(
    "ise_dataconnect_posture_eligible_recent_assessment_ratio",
    "Fraction of posture-applicable endpoints assessed in the configured reporting window")
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

ise_dataconnect_endpoints_total = Gauge(
    "ise_dataconnect_endpoints_total", "Current endpoints exposed by Data Connect")
ise_dataconnect_endpoints_unknown_profile_total = Gauge(
    "ise_dataconnect_endpoints_unknown_profile_total",
    "Exact current endpoint count with a missing or unknown endpoint policy")
ise_dataconnect_endpoint_field_populated = Gauge(
    "ise_dataconnect_endpoint_field_populated",
    "Current endpoints with a populated operational inventory field", ["field"])
ise_dataconnect_endpoint_field_coverage_ratio = Gauge(
    "ise_dataconnect_endpoint_field_coverage_ratio",
    "Fraction of current endpoints with a populated operational inventory field", ["field"])
ise_dataconnect_endpoints_stale = Gauge(
    "ise_dataconnect_endpoints_stale",
    "Current endpoints not updated within the configured age threshold", ["age_days"])
ise_dataconnect_profiled_endpoint_group_memberships_total = Gauge(
    "ise_dataconnect_profiled_endpoint_group_memberships_total",
    "Exact sum of distinct endpoint memberships across profiling groups in the reporting window")
ise_dataconnect_endpoints_by_profile = Gauge(
    "ise_dataconnect_endpoints_by_profile", "Current endpoints by endpoint policy",
    ["profile"])
ise_dataconnect_endpoints_by_identity_group = Gauge(
    "ise_dataconnect_endpoints_by_identity_group", "Current endpoints by identity-group ID",
    ["identity_group"])
ise_dataconnect_endpoints_by_posture_applicable = Gauge(
    "ise_dataconnect_endpoints_by_posture_applicable",
    "Current endpoints by posture-applicable state", ["applicable"])
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

ise_dataconnect_view_has_rows = Gauge(
    "ise_dataconnect_view_has_rows",
    "Whether each bounded Data Connect reporting view contains at least one row",
    ["view", "domain"])
ise_dataconnect_view_newest_event_timestamp = Gauge(
    "ise_dataconnect_view_newest_event_timestamp",
    "Newest source-event timestamp visible in each Data Connect reporting view",
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
