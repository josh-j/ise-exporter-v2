"""Lab-only Prometheus coverage target for exercising every Grafana panel.

The service mirrors a real exporter target and adds deterministic samples for
states that should not be manufactured on a production ISE deployment. Grafana
gets a separate selectable deployment instead of synthetic series being mixed
into the truthful live target.
"""

from __future__ import annotations

import argparse
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen

LOG = logging.getLogger("ise_dashboard_coverage")

# No-label Gauges are always emitted by prometheus_client, even when their
# collector is disabled. Replace these samples rather than creating duplicates.
_REPLACED_METRICS = frozenset({
    "ise_endpoint_fleet_assessed_total",
    "ise_endpoint_fleet_cache_entries",
    "ise_endpoint_fleet_compliance_ratio",
    "ise_endpoint_fleet_coverage_ratio",
    "ise_endpoint_fleet_eligible_total",
    "ise_endpoint_fleet_oldest_assessment_age_seconds",
    "ise_dataconnect_radius_accounting_tail_total",
    "ise_dataconnect_radius_authentication_tail_total",
})

_STATIC_SAMPLES = """
ise_dataconnect_radius_accounting_session_seconds{stat="p95",nad="coverage-nad",psn="laba-ise-003"} 720
ise_network_device_ndg_assignment{nad="coverage-nad",location="Coverage Lab",ops_owner="Coverage",device_type="Simulator"} 1
ise_dataconnect_radius_errors{message_code="54321",message_text="Coverage simulated RADIUS error",nad="coverage-nad",authentication_method="PAP",psn="laba-ise-003"} 2
ise_dataconnect_profile_events{profile="Coverage Endpoint",source="RADIUS Probe",action="profiled",identity_group="Coverage Identity Group"} 4
ise_nad_authentication_events{nad="coverage-nad",status="passed"} 9
ise_nad_authentication_events{nad="coverage-nad",status="failed"} 2
ise_dataconnect_schema_view_available{view="COVERAGE_MISSING_VIEW",requirement="dataset"} 0
ise_dataconnect_schema_column_available{view="COVERAGE_VIEW",column="OPTIONAL_COVERAGE_COLUMN",requirement="optional"} 0
ise_dataconnect_tail_cursor_id{view="coverage_cursor"} 4242
ise_dataconnect_tail_resets_total{view="coverage_cursor"} 1
ise_endpoint_fleet_assessed_total 80
ise_endpoint_fleet_eligible_total 100
ise_endpoint_fleet_coverage_ratio 0.8
ise_endpoint_fleet_compliance_ratio 0.75
ise_endpoint_fleet_cache_entries 80
ise_endpoint_fleet_oldest_assessment_age_seconds 3600
ise_endpoint_fleet_posture{status="Compliant"} 60
ise_endpoint_fleet_posture{status="NonCompliant"} 20
ise_endpoint_fleet_by_os{os="CoverageOS"} 80
ise_endpoint_fleet_by_agent_version{agent_version="5.1.coverage"} 80
ise_endpoint_fleet_by_policy{policy="Coverage Posture Policy"} 80
ise_endpoint_fleet_by_psn{psn="laba-ise-003"} 80
ise_dataconnect_diagnostic_events{source="coverage",node="laba-ise-001",severity="warning",category="system",message_code="COV-PAN"} 1
ise_dataconnect_diagnostic_events{source="coverage",node="laba-ise-002",severity="warning",category="system",message_code="COV-MNT"} 1
ise_dataconnect_diagnostic_events{source="coverage",node="laba-ise-003",severity="error",category="radius",message_code="COV-PSN"} 2
ise_mnt_active_posture_endpoints{status="Compliant",os="CoverageOS",psn="laba-ise-003"} 6
ise_mnt_active_posture_endpoints{status="NonCompliant",os="CoverageOS",psn="laba-ise-003"} 2
ise_mnt_active_posture_policy_results{policy="Coverage Policy",result="passed"} 6
ise_mnt_active_posture_policy_results{policy="Coverage Policy",result="failed"} 2
ise_mnt_active_posture_endpoints_by_ops_owner{ops_owner="Coverage",status="Compliant"} 6
ise_mnt_active_posture_endpoints_by_ops_owner{ops_owner="Coverage",status="NonCompliant"} 2
ise_dataconnect_posture_endpoint_assessments{status="Compliant",os="CoverageOS",agent_version="5.1.coverage",policy="Coverage Policy",psn="laba-ise-003"} 6
ise_dataconnect_posture_endpoint_assessments{status="Failed",os="CoverageOS",agent_version="5.1.coverage",policy="Coverage Policy",psn="laba-ise-003"} 2
ise_dataconnect_posture_enforcement_assessments{enforcement="Quarantine",enforcement_type="AuthorizationProfile",enforcement_status="Applied",posture_status="Failed",psn="laba-ise-003"} 2
ise_dataconnect_posture_condition_assessments{policy="Coverage Policy",policy_status="Failed",condition="Coverage Condition",condition_status="Failed",enforcement="Quarantine"} 2
ise_dataconnect_posture_failures{message_code="POSTURE-COVERAGE",status="Failed",policy="Coverage Policy",psn="laba-ise-003"} 2
ise_tacacs_suspected_unused_internal_user{username="coverage-unused",reason="no_recent_activity"} 1
ise_tacacs_internal_user_hygiene_risk{username="coverage-unused",risk="password_never_expires"} 1
ise_tacacs_account_authentication_events{username="coverage-admin",status="passed",device="coverage-nad",policy="Coverage Device Admin",identity_store="Internal Users",failure_class="none"} 4
ise_tacacs_account_authentication_events{username="coverage-admin",status="failed",device="coverage-nad",policy="Coverage Device Admin",identity_store="Internal Users",failure_class="invalid_credentials"} 1
ise_tacacs_account_authorization_events{username="coverage-admin",status="passed",device="coverage-nad",policy="Coverage Device Admin",shell_profile="Coverage Shell",command_set="Coverage Commands"} 3
ise_tacacs_accounting_events{username="coverage-admin",status="passed",device="coverage-nad",command_family="show"} 5
""".strip()


def _metric_name(line: str) -> str:
    return line.split("{", 1)[0].split(" ", 1)[0]


def _keep_upstream_line(line: str) -> bool:
    if not line or line.startswith("#"):
        return True
    name = _metric_name(line)
    if name in _REPLACED_METRICS:
        return False
    if name in {"ise_dataset_up", "ise_dataset_fresh"}:
        return 'dataset="endpoint_fleet"' not in line
    return True


def render_coverage_metrics(upstream: str, *, now: float | None = None) -> str:
    """Return a valid mirrored Prometheus exposition with the coverage overlay."""
    timestamp = int(time.time() if now is None else now)
    mirrored = "\n".join(
        line for line in upstream.rstrip().splitlines() if _keep_upstream_line(line)
    )
    dynamic = "\n".join((
        'ise_dataset_up{dataset="endpoint_fleet",source="dataconnect"} 1',
        'ise_dataset_fresh{dataset="endpoint_fleet",source="dataconnect"} 1',
        (
            'ise_dataconnect_radius_error_tail_total'
            '{message_code="54321",psn="laba-ise-003"} '
            f"{timestamp}"
        ),
        (
            'ise_dataconnect_posture_assessment_tail_total'
            '{status="Failed",psn="laba-ise-003"} '
            f"{timestamp}"
        ),
        (
            'ise_dataconnect_radius_accounting_tail_total'
            '{event_type="start",psn="laba-ise-003"} '
            f"{timestamp * 2}"
        ),
        (
            'ise_dataconnect_radius_accounting_tail_total'
            '{event_type="stop",psn="laba-ise-003"} '
            f"{timestamp}"
        ),
        (
            'ise_dataconnect_radius_authentication_tail_total'
            '{result="passed",psn="laba-ise-003"} '
            f"{timestamp * 3}"
        ),
        (
            'ise_dataconnect_radius_authentication_tail_total'
            '{result="failed",psn="laba-ise-003"} '
            f"{timestamp}"
        ),
    ))
    return f"{mirrored}\n{_STATIC_SAMPLES}\n{dynamic}\n"


def make_handler(upstream: str, timeout: float):
    class CoverageHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler contract
            if self.path == "/healthz":
                self._respond(200, b"ok\n", "text/plain; charset=utf-8")
                return
            if self.path != "/metrics":
                self._respond(404, b"not found\n", "text/plain; charset=utf-8")
                return
            try:
                with urlopen(upstream, timeout=timeout) as response:
                    source = response.read().decode("utf-8")
                body = render_coverage_metrics(source).encode("utf-8")
                self._respond(200, body, "text/plain; version=0.0.4; charset=utf-8")
            except Exception as error:  # pragma: no cover - HTTP integration path
                LOG.error("could not mirror upstream exporter: %s", error)
                self._respond(502, b"upstream exporter unavailable\n", "text/plain")

        def log_message(self, fmt, *args):
            LOG.debug(fmt, *args)

        def _respond(self, status: int, body: bytes, content_type: str):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return CoverageHandler


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Mirror an ISE exporter and add lab-only dashboard coverage samples")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9619)
    parser.add_argument("--upstream", default="http://127.0.0.1:9618/metrics")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
    server = ThreadingHTTPServer(
        (args.listen, args.port), make_handler(args.upstream, args.timeout))
    LOG.info(
        "dashboard coverage target listening on %s:%d; upstream=%s",
        args.listen, args.port, args.upstream)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
