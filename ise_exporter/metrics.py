"""Central metric registry — the single import surface for every collector and
the stream projector. This is what eliminates the cross-file `noqa: F821`
globals: collectors do `from ise_exporter.metrics import ise_active_sessions`
instead of referencing a name defined in some other module."""
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

# --- sessions (poll) ---
ise_active_sessions = Gauge("ise_active_sessions_total", "Total active RADIUS sessions")
ise_radius_sessions_by_nad = Gauge("ise_radius_sessions_by_nad", "Sessions per NAD", ["nas_hostname", "location"])
ise_radius_sessions_by_ops_owner = Gauge("ise_radius_sessions_by_ops_owner", "Sessions per ops owner", ["ops_owner"])
ise_radius_sessions_by_psn = Gauge("ise_radius_sessions_by_psn", "Sessions per PSN", ["psn"])

# --- authz (poll fan-out OR stream projection) ---
ise_session_status_endpoints = Gauge("ise_session_status_endpoints", "Unique endpoints per NAD by status", ["nad_hostname", "location", "ops_owner", "status"])
ise_session_failure_reasons = Gauge("ise_session_failure_reasons", "Unique endpoints by failure reason", ["reason_code", "nad_hostname", "location", "ops_owner"])
ise_session_auth_methods = Gauge("ise_session_auth_methods", "Unique endpoints by auth method", ["method", "nad_hostname", "location", "ops_owner"])
ise_session_failure_auth_methods = Gauge("ise_session_failure_auth_methods", "Unique failed endpoints by auth method", ["method", "nad_hostname", "location", "ops_owner"])
ise_authz_unique_endpoints_by_profile = Gauge("ise_authz_unique_endpoints_by_profile", "Unique endpoints per authz profile", ["authz_profile", "nad_hostname", "location", "ops_owner"])
ise_session_authz_rule_endpoints = Gauge("ise_session_authz_rule_endpoints", "Unique endpoints per matched authz rule", ["authz_rule", "nad_hostname", "location", "ops_owner"])
ise_session_policy_set_endpoints = Gauge("ise_session_policy_set_endpoints", "Unique endpoints per policy set", ["policy_set", "nad_hostname", "location", "ops_owner"])
ise_session_detail_cache_size = Gauge("ise_session_detail_cache_size", "Cached Session/MACAddress entries")
ise_session_warmup_progress = Gauge("ise_session_warmup_progress", "Authz cache warmup fraction (0-1)")
ise_session_detail_fetches_total = Counter("ise_session_detail_fetches_total", "Session/MACAddress fetches", ["result"])
# RADIUS auth transaction latency (ISE's TotalAuthenLatency, ms -> seconds). ISE evaluates
# authentication and authorization in one policy pass, so this single figure covers the whole
# authC+authZ transaction — there is no separate authorization-latency field. Observed ONCE per
# session detail fetch (not per scrape) so each authentication contributes exactly one sample.
ise_radius_auth_latency_seconds = Histogram(
    "ise_radius_auth_latency_seconds",
    "RADIUS authentication+authorization transaction latency (ISE TotalAuthenLatency)",
    ["nad_hostname", "location", "ops_owner", "status"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
ise_radius_auth_latency_by_psn_seconds = Histogram(
    "ise_radius_auth_latency_by_psn_seconds",
    "RADIUS authentication+authorization transaction latency by PSN",
    ["psn", "status"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
ise_radius_client_latency_seconds = Histogram(
    "ise_radius_client_latency_seconds",
    "Client-side latency reported by ISE",
    ["psn", "status"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5])
ise_radius_step_latency_seconds = Histogram(
    "ise_radius_step_latency_seconds",
    "Per-execution-step latency reported by ISE StepLatency, keyed by execution step code",
    ["psn", "step_code", "status"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5])

# --- posture / device trust (Secure Client) ---
# Unique endpoints (distinct MAC) per posture status, per site/ops-owner. Populated
# by the pxGrid projector (session `postureStatus`) in stream mode and by the authz
# poll fan-out (session detail) otherwise — same poll-vs-stream ownership split as
# ise_session_status_endpoints.
ise_session_posture_status = Gauge("ise_session_posture_status", "Unique endpoints by posture compliance status", ["status", "location", "ops_owner"])
# MDM device-trust dimensions (registered/compliant/disk_encrypted/jailbroken/pin_locked),
# value true|false|unknown, per ops-owner. Stream-sourced only — the pxGrid session object
# carries the mdm* fields; empty in poll mode (MnT ActiveList doesn't).
ise_session_mdm_status = Gauge("ise_session_mdm_status", "Unique MDM-managed endpoints by dimension/value", ["dimension", "value", "ops_owner"])
# Secure Client / posture agent version from getEndpoints endpoint attributes
# (PostureAgentVersion / SecureClientVersion / ...). Best-effort: only emitted for
# endpoints that expose a version attribute (see dashboards/README.md).
ise_endpoints_by_secureclient_version = Gauge("ise_endpoints_by_secureclient_version", "Endpoints per Secure Client / posture agent version", ["version"])
# Per posture-POLICY pass/fail, parsed from each endpoint's PostureReport attribute
# collected via getEndpoints (NOT the endpoint topic, NOT MnT session detail). `result`
# is the policy-level roll-up (Passed/Failed/...), `policy` the ISE posture policy name
# (encodes the check); ops_owner is joined from the endpoint's live session when known.
ise_posture_policy_result = Gauge("ise_posture_policy_result", "Unique endpoints per posture policy by result", ["policy", "result", "ops_owner"])

# --- network devices ---
ise_network_devices_total = Gauge("ise_network_devices_total", "Total network devices")
ise_network_devices_by_location = Gauge("ise_network_devices_by_location", "Devices per location", ["location"])
ise_network_devices_by_ops_owner = Gauge("ise_network_devices_by_ops_owner", "Devices per ops owner", ["ops_owner"])
ise_network_devices_by_type = Gauge("ise_network_devices_by_type", "Devices by type", ["device_type"])

# --- endpoints (count + model breakdown) ---
ise_endpoints_total = Gauge("ise_endpoints_total", "Total endpoints")
ise_endpoints_by_hardware_model = Gauge("ise_endpoints_by_hardware_model", "Endpoints per MFC hardware model", ["model"])
ise_endpoints_by_manufacturer = Gauge("ise_endpoints_by_manufacturer", "Endpoints per manufacturer", ["manufacturer"])
ise_endpoints_by_endpoint_type = Gauge("ise_endpoints_by_endpoint_type", "Endpoints per MFC endpoint type", ["endpoint_type"])
ise_endpoints_by_os = Gauge("ise_endpoints_by_os", "Endpoints per MFC OS", ["os"])
ise_endpoints_by_policy = Gauge("ise_endpoints_by_policy", "Endpoints per profiling policy name", ["policy"])
ise_endpoints_pxgrid_total = Gauge("ise_endpoints_pxgrid_total", "Endpoints returned by pxGrid getEndpoints")
ise_endpoint_mfc_coverage = Gauge("ise_endpoint_mfc_coverage", "Fraction with non-empty MFC attribute", ["attribute"])

# --- endpoint profiler hierarchy (policy catalog joined onto by-policy counts) ---
ise_endpoints_by_profile_all = Gauge("ise_endpoints_by_profile_all", "Endpoints per profiling policy with category/parent hierarchy", ["category", "parent", "profile"])
ise_profiler_policies_total = Gauge("ise_profiler_policies_total", "Profiling policies defined in ISE's profiler catalog (pxGrid getProfiles)")
ise_profiler_hierarchy_age_seconds = Gauge("ise_profiler_hierarchy_age_seconds", "Seconds since the profiler policy hierarchy was last refreshed from pxGrid")

# --- ERS endpoint detail sweep (/ers/config/endpoint/{id}) ---
ise_endpoint_attribute_cache_entries = Gauge("ise_endpoint_attribute_cache_entries", "Endpoints with cached ERS endpoint detail/profile-attribute data")
ise_endpoint_attribute_scan_last_count = Gauge("ise_endpoint_attribute_scan_last_count", "Endpoint records fetched or refreshed by the last ERS endpoint-attribute collector run")
ise_endpoint_attribute_fetch_errors = Gauge("ise_endpoint_attribute_fetch_errors", "Endpoint records that failed during the last ERS endpoint-attribute scan", ["stage"])
ise_endpoint_attribute_coverage = Gauge("ise_endpoint_attribute_coverage", "Fraction of cached endpoints with a selected ERS endpoint attribute", ["attribute"])
ise_endpoints_by_profiled_policy = Gauge("ise_endpoints_by_profiled_policy", "Cached endpoints per profiler policy from the ERS endpoint object (profileId)", ["policy"])
ise_endpoints_by_identity_group = Gauge("ise_endpoints_by_identity_group", "Cached endpoints per endpoint identity group from ERS endpoint detail", ["group"])
ise_endpoint_static_assignment = Gauge("ise_endpoint_static_assignment", "Cached endpoints by static assignment flag from ERS endpoint detail", ["assignment", "value"])
ise_endpoint_custom_attribute_value = Gauge("ise_endpoint_custom_attribute_value", "Cached endpoints by configured custom endpoint attribute key/value", ["key", "value"])

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
ise_tacacs_policy_set_hits = Gauge(
    "ise_tacacs_policy_set_hits", "Device Admin policy-set hit count",
    ["policy_set", "state", "service"])
ise_tacacs_authentication_rule_hits = Gauge(
    "ise_tacacs_authentication_rule_hits", "Device Admin authentication-rule hit count",
    ["policy_set", "rule", "state", "identity_source"])
ise_tacacs_authorization_rule_hits = Gauge(
    "ise_tacacs_authorization_rule_hits", "Device Admin authorization-rule hit count",
    ["policy_set", "rule", "state", "profile", "command_sets"])
ise_tacacs_policy_objects_total = Gauge(
    "ise_tacacs_policy_objects_total", "Configured Device Admin objects by type",
    ["object_type"])

# --- exporter self-observability ---
ise_scrape_duration_seconds = Histogram("ise_scrape_duration_seconds", "Scrape time", buckets=[1, 5, 10, 30, 60, 120, 300])
ise_scrape_errors_total = Counter("ise_scrape_errors_total", "Scrape errors", ["collector", "error_type"])
ise_api_requests_total = Counter("ise_api_requests_total", "API requests", ["api", "status"])
ise_api_errors_total = Counter("ise_api_errors_total", "API errors", ["api", "error_type", "http_code"])
ise_collector_duration_seconds = Gauge("ise_collector_duration_seconds", "Per-collector duration", ["collector"])
ise_last_successful_scrape = Gauge("ise_last_successful_scrape_timestamp", "Last success ts", ["collector"])
ise_consecutive_failures = Gauge("ise_consecutive_failures", "Consecutive failures", ["collector"])
ise_collector_enabled = Gauge("ise_collector_enabled", "Collector enabled", ["collector"])

# --- pxGrid stream health ---
ise_pxgrid_connected = Gauge("ise_pxgrid_connected", "pxGrid pubsub state (1=live)")
ise_pxgrid_last_event_timestamp = Gauge("ise_pxgrid_last_event_timestamp", "Last topic event ts")
ise_pxgrid_resync_total = Counter("ise_pxgrid_resync_total", "Full re-baselines", ["reason"])
ise_pxgrid_state_size = Gauge("ise_pxgrid_state_size", "Streamed state entries", ["topic"])
ise_pxgrid_events_total = Counter("ise_pxgrid_events_total", "Topic events processed", ["topic", "phase"])
