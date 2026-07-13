"""Central metric registry and the only metric import surface for collectors."""
from prometheus_client import Gauge, Counter, Info, Enum, Histogram

# --- availability / deployment ---
ise_up = Gauge("ise_up", "ISE API availability (1=up, 0=down)")
ise_info = Info("ise", "ISE deployment info")
ise_deployment_status = Enum(
    "ise_deployment_status", "Status of nodes in deployment",
    labelnames=["node", "roles", "services"],
    states=["Connected", "Disconnected", "Registering", "Syncing", "Unknown"])
ise_node_count = Gauge("ise_node_count", "Number of nodes by role", ["role"])
ise_pan_ha_enabled = Gauge("ise_pan_ha_enabled", "PAN HA enabled (1=yes, 0=no)")

# --- network devices ---
ise_network_devices_total = Gauge("ise_network_devices_total", "Total network devices")
ise_network_devices_by_location = Gauge("ise_network_devices_by_location", "Devices per location", ["location"])
ise_network_devices_by_ops_owner = Gauge("ise_network_devices_by_ops_owner", "Devices per ops owner", ["ops_owner"])
ise_network_devices_by_type = Gauge("ise_network_devices_by_type", "Devices by type", ["device_type"])

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
ise_tacacs_internal_user_detail_coverage = Gauge(
    "ise_tacacs_internal_user_detail_coverage",
    "Fraction of enumerated internal users whose ERS detail was successfully fetched")
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
    "Internal-user candidate for review based on account object age",
    ["username", "reason"])
ise_tacacs_internal_user_hygiene_risk = Gauge(
    "ise_tacacs_internal_user_hygiene_risk", "Internal-user account hygiene review finding",
    ["username", "risk"])
ise_tacacs_policy_objects_total = Gauge(
    "ise_tacacs_policy_objects_total", "Configured Device Admin objects by type",
    ["object_type"])
ise_tacacs_dataconnect_up = Gauge(
    "ise_tacacs_dataconnect_up", "ISE Data Connect TACACS query status (1=successful)")
ise_tacacs_account_authentication_events = Gauge(
    "ise_tacacs_account_authentication_events",
    "TACACS authentication events in Data Connect's last-two-days view",
    ["username", "status", "device", "policy", "identity_store", "failure_reason"])
ise_tacacs_account_authorization_events = Gauge(
    "ise_tacacs_account_authorization_events",
    "TACACS authorization events in Data Connect's last-two-days view",
    ["username", "status", "device", "policy", "shell_profile", "command_set", "command"])
ise_tacacs_accounting_events = Gauge(
    "ise_tacacs_accounting_events",
    "TACACS accounting events in Data Connect's last-two-days view",
    ["username", "status", "device", "command"])
ise_tacacs_account_last_seen_timestamp = Gauge(
    "ise_tacacs_account_last_seen_timestamp",
    "Most recent TACACS event timestamp from Data Connect",
    ["username", "event_type"])

# --- Data Connect reporting plane ---
# These metrics are populated only by the Data Connect domain collectors.  REST
# and legacy MnT collectors must not write them, which keeps ownership and
# snapshot semantics explicit.
ise_dataconnect_radius_authentication_events = Gauge(
    "ise_dataconnect_radius_authentication_events",
    "RADIUS authentication events in the bounded Data Connect reporting window",
    ["status", "authentication_method", "authentication_protocol", "nad", "policy_set", "psn"])
ise_dataconnect_radius_response_time_seconds = Gauge(
    "ise_dataconnect_radius_response_time_seconds",
    "RADIUS response-time aggregate from Data Connect",
    ["stat", "status", "nad", "psn"])
ise_dataconnect_radius_accounting_events = Gauge(
    "ise_dataconnect_radius_accounting_events",
    "RADIUS accounting events in the bounded Data Connect reporting window",
    ["event_type", "nad", "authorization_policy", "psn"])
ise_dataconnect_radius_accounting_session_seconds = Gauge(
    "ise_dataconnect_radius_accounting_session_seconds",
    "RADIUS accounting session-time aggregate from Data Connect",
    ["stat", "nad", "psn"])
ise_dataconnect_radius_active_sessions = Gauge(
    "ise_dataconnect_radius_active_sessions",
    "Likely active sessions based on each accounting session ID's latest record",
    ["nad", "psn"])
ise_dataconnect_radius_errors = Gauge(
    "ise_dataconnect_radius_errors",
    "RADIUS errors grouped by stable troubleshooting dimensions",
    ["message_code", "nad", "authentication_method", "psn"])

ise_dataconnect_posture_endpoint_assessments = Gauge(
    "ise_dataconnect_posture_endpoint_assessments",
    "Distinct endpoints assessed by posture status, OS, agent, policy, and PSN",
    ["status", "os", "agent_version", "policy", "psn"])
ise_dataconnect_posture_condition_assessments = Gauge(
    "ise_dataconnect_posture_condition_assessments",
    "Distinct endpoints assessed by posture policy condition and result",
    ["policy", "policy_status", "condition", "condition_status", "enforcement"])
ise_dataconnect_posture_failures = Gauge(
    "ise_dataconnect_posture_failures",
    "Distinct failed posture endpoints grouped by message code and policy",
    ["message_code", "status", "policy", "psn"])

ise_dataconnect_endpoints_total = Gauge(
    "ise_dataconnect_endpoints_total", "Current endpoints exposed by Data Connect")
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

# --- exporter self-observability ---
ise_dataset_up = Gauge(
    "ise_dataset_up", "Authoritative dataset collection status (1=successful)",
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
