"""Read-only Cisco ISE operator CLI built on the exporter's API client.

The command surface intentionally exposes GET operations only. Inventory commands
are bounded by default so an exploratory query cannot accidentally enumerate an
100k-endpoint deployment; callers must opt into ``--all`` explicitly.
"""
from __future__ import annotations

import argparse
import atexit
import cmd
import contextlib
import csv
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import sys
import time

from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.pretty import Pretty
from rich.table import Table
from rich.text import Text

from . import version_string
from .clients.dataconnect import DataConnectClient
from .clients.rest import ERS_MAX_PAGES, ISEOperatorClient
from .collectors.dataconnect_common import recent_event_predicate
from .config import Config
from .dataconnect_schema import metadata_rows, schema_by_table, table_columns
from .util import (first_nonempty, is_mac, normalize_agent_version, normalize_mac,
                   normalize_posture,
                   parse_other_attr_string, parse_posture_report)


# MnT AuthStatus is a live troubleshooting API whose cost grows with both the
# requested lookback and result count.  Keep the everyday command deliberately
# small, require an explicit acknowledgement above it, and retain a hard ceiling
# even when expensive operations are enabled.
AUTH_STATUS_SAFE_SECONDS = 3600
AUTH_STATUS_SAFE_LIMIT = 100
AUTH_STATUS_MAX_SECONDS = 86400
AUTH_STATUS_MAX_LIMIT = 1000


COMMAND_SCHEMAS = {
    "health": {
        "api": "ERS + MnT + optional Data Connect",
        "host_env": ["ISE_HOST", "ISE_MNT_HOST", "ISE_DATACONNECT_HOST"],
        "method": "GET + SELECT", "paths": [
            "/ers/config/networkdevice?size=1&page=1",
            "/admin/API/mnt/Session/ActiveCount",
        ],
        "fields": [
            "service", "host", "reachable", "authenticated", "http_status",
            "probe_status"],
    },
    "endpoints": {
        "api": "Data Connect + ERS", "host_env": ["ISE_DATACONNECT_HOST", "ISE_HOST"],
        "method": "SELECT or GET", "path": "/ers/config/endpoint",
        "bounded_default": 100,
    },
    "endpoint-fields": {
        "api": "Data Connect metadata", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "view": "USER_TAB_COLUMNS", "reads_event_rows": False,
    },
    "endpoint": {
        "api": "Data Connect + ERS + optional MnT",
        "host_env": ["ISE_HOST", "ISE_MNT_HOST", "ISE_DATACONNECT_HOST"],
        "method": "SELECT + GET", "paths": [
            "/ers/config/endpoint?filter=mac.EQ.{identifier}",
            "/ers/config/endpoint/{id}",
            "/admin/API/mnt/Session/MACAddress/{mac}",
        ],
        "identifiers": ["MAC (any common format)", "IP", "hostname", "ERS id"],
    },
    "resolve": {
        "api": "Data Connect + ERS + MnT",
        "host_env": ["ISE_HOST", "ISE_MNT_HOST", "ISE_DATACONNECT_HOST"],
        "method": "SELECT + GET", "identifiers": [
            "MAC (any common format)", "IP", "hostname", "ERS id"],
    },
    "session": {
        "api": "MnT XML + endpoint resolver", "host_env": "ISE_MNT_HOST",
        "method": "GET", "paths": [
            "/admin/API/mnt/Session/MACAddress/{mac}",
            "/admin/API/mnt/Session/IPAddress/{ip}",
        ],
    },
    "sessions": {
        "api": "MnT XML", "host_env": "ISE_MNT_HOST", "method": "GET",
        "path": "/admin/API/mnt/Session/ActiveList",
    },
    "auth-status": {
        "api": "MnT XML", "host_env": "ISE_MNT_HOST", "method": "GET",
        "path": "/admin/API/mnt/AuthStatus/MACAddress/{mac}/{seconds}/{limit}/All",
        "identifiers": ["MAC (any common format)", "IP", "hostname", "ERS id"],
        "bounded_default": {"seconds": 600, "limit": 20},
        "production_safe_max": {"seconds": 3600, "limit": 100},
        "hard_max": {"seconds": 86400, "limit": 1000},
    },
    "secure-client": {
        "api": "MnT XML", "host_env": "ISE_MNT_HOST", "method": "GET",
        "path": "/admin/API/mnt/Session/MACAddress/{mac}",
        "identifiers": ["MAC (any common format)", "IP", "hostname", "ERS id"],
        "fields": ["PostureAgentVersion", "PostureApplicable",
                   "PostureAssessmentStatus", "PostureReport", "PostureStatus"],
    },
    "nads": {
        "api": "ERS", "host_env": "ISE_HOST", "method": "GET",
        "path": "/ers/config/networkdevice", "bounded_default": 100,
    },
    "nodes": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/deployment/node",
    },
    "profiles": {
        "api": "ERS", "host_env": "ISE_HOST", "method": "GET",
        "path": "/ers/config/profilerprofile", "bounded_default": 100,
    },
    "tacacs-users": {
        "api": "ERS", "host_env": "ISE_HOST", "method": "GET",
        "path": "/ers/config/internaluser", "bounded_default": 100,
    },
    "identity-groups": {
        "api": "ERS", "host_env": "ISE_HOST", "method": "GET",
        "path": "/ers/config/identitygroup", "bounded_default": 100,
    },
    "network-device-groups": {
        "api": "ERS", "host_env": "ISE_HOST", "method": "GET",
        "path": "/ers/config/networkdevicegroup", "bounded_default": 100,
    },
    "licenses": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/license/system/tier-state",
    },
    "patches": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/patch",
    },
    "backup-status": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/backup-restore/config/last-backup-status",
    },
    "repositories": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/repository",
    },
    "network-policy-sets": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/policy/network-access/policy-set",
    },
    "device-admin-policy-sets": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/policy/device-admin/policy-set",
    },
    "authorization-profiles": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/policy/network-access/authorization-profiles",
    },
    "tacacs-command-sets": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/policy/device-admin/command-sets",
    },
    "tacacs-shell-profiles": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "path": "/api/v1/policy/device-admin/shell-profiles",
    },
    "certificates": {
        "api": "OpenAPI", "host_env": "ISE_HOST", "method": "GET",
        "paths": [
            "/api/v1/certs/system-certificate/{hostname}",
            "/api/v1/certs/trusted-certificate",
        ],
    },
    "radius-auth": {
        "api": "Data Connect", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "view": "RADIUS_AUTHENTICATIONS",
        "bounded_default": 100,
    },
    "endpoint-report": {
        "api": "Data Connect", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "view": "ENDPOINTS_DATA", "bounded_default": 100,
    },
    "radius-errors": {
        "api": "Data Connect", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "view": "RADIUS_ERRORS_VIEW", "bounded_default": 100,
    },
    "radius-accounting": {
        "api": "Data Connect", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "view": "RADIUS_ACCOUNTING", "bounded_default": 100,
    },
    "posture": {
        "api": "Data Connect", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "views": [
            "POSTURE_ASSESSMENT_BY_ENDPOINT", "POSTURE_ASSESSMENT_BY_CONDITION"],
        "bounded_default": 100,
    },
    "psn-metrics": {
        "api": "Data Connect", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "view": "KEY_PERFORMANCE_METRICS", "bounded_default": 100,
    },
    "tacacs-activity": {
        "api": "Data Connect", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "views": [
            "TACACS_AUTHENTICATION_LAST_TWO_DAYS",
            "TACACS_AUTHORIZATION_LAST_TWO_DAYS",
            "TACACS_ACCOUNTING_LAST_TWO_DAYS",
        ], "bounded_default": 100,
    },
    "dataconnect-schema": {
        "api": "Data Connect metadata", "host_env": "ISE_DATACONNECT_HOST",
        "method": "SELECT", "view": "USER_TAB_COLUMNS", "reads_event_rows": False,
    },
    "get": {
        "api": "ERS, OpenAPI, or MnT", "method": "GET only",
        "host_env": {"ers": "ISE_HOST", "openapi": "ISE_HOST", "mnt": "ISE_MNT_HOST"},
    },
}


ERS_INVENTORIES = {
    "endpoints": "/config/endpoint",
    "nads": "/config/networkdevice",
    "profiles": "/config/profilerprofile",
    "tacacs-users": "/config/internaluser",
    "identity-groups": "/config/identitygroup",
    "network-device-groups": "/config/networkdevicegroup",
}

OPENAPI_INVENTORIES = {
    "licenses": ("/license/system/tier-state", False),
    "patches": ("/patch", True),
    "backup-status": ("/backup-restore/config/last-backup-status", True),
    "repositories": ("/repository", True),
    "network-policy-sets": ("/policy/network-access/policy-set", True),
    "device-admin-policy-sets": ("/policy/device-admin/policy-set", True),
    "authorization-profiles": ("/policy/network-access/authorization-profiles", True),
    "tacacs-command-sets": ("/policy/device-admin/command-sets", True),
    "tacacs-shell-profiles": ("/policy/device-admin/shell-profiles", True),
}

DATACONNECT_REPORTS = {
    "endpoint-report": {
        "table": "ENDPOINTS_DATA",
        "columns": (
            "ID", "ENDPOINT_ID", "MAC_ADDRESS", "ENDPOINT_IP", "HOSTNAME", "ENDPOINT_POLICY",
            "IDENTITY_GROUP_ID", "POSTURE_APPLICABLE", "PORTAL_USER",
            "PROFILE_SERVER", "CREATE_TIME", "UPDATE_TIME"),
    },
    "radius-auth": {
        "table": "RADIUS_AUTHENTICATIONS",
        "columns": (
            "TIMESTAMP", "USERNAME", "CALLING_STATION_ID", "FRAMED_IP_ADDRESS",
            "DEVICE_NAME", "ISE_NODE", "AUTHENTICATION_METHOD",
            "AUTHENTICATION_PROTOCOL", "AUTHORIZATION_POLICY", "POLICY_SET_NAME",
            "FAILED", "RESPONSE_TIME"),
    },
    "radius-errors": {
        "table": "RADIUS_ERRORS_VIEW",
        "columns": (
            "TIMESTAMP", "USERNAME", "CALLING_STATION_ID", "FRAMED_IP_ADDRESS",
            "NETWORK_DEVICE_NAME", "ISE_NODE", "AUTHENTICATION_METHOD",
            "MESSAGE_CODE", "FAILURE_REASON"),
    },
    "radius-accounting": {
        "table": "RADIUS_ACCOUNTING",
        "columns": (
            "TIMESTAMP", "USERNAME", "CALLING_STATION_ID", "FRAMED_IP_ADDRESS",
            "DEVICE_NAME", "ISE_NODE", "ACCT_STATUS_TYPE", "ACCT_SESSION_ID",
            "ACCT_SESSION_TIME", "AUTHORIZATION_POLICY"),
    },
    "posture": {
        "table": "POSTURE_ASSESSMENT_BY_ENDPOINT",
        "condition_table": "POSTURE_ASSESSMENT_BY_CONDITION",
        "columns": (
            "TIMESTAMP", "LOGGED_AT", "ENDPOINT_MAC_ADDRESS", "IP_ADDRESS",
            "ENDPOINT_OPERATING_SYSTEM", "ENDPOINT_OS", "ISE_NODE",
            "POSTURE_AGENT_VERSION", "POSTURE_STATUS", "POSTURE_POLICY_MATCHED",
            "POLICY", "POLICY_STATUS", "CONDITION_NAME", "CONDITION_STATUS",
            "FAILURE_REASON", "MESSAGE_CODE"),
    },
    "psn-metrics": {
        "table": "KEY_PERFORMANCE_METRICS",
        "columns": (
            "LOGGED_TIME", "ISE_NODE", "RADIUS_REQUESTS_HR", "LOGGED_TO_MNT_HR",
            "NOISE_HR", "SUPPRESSION_HR", "AVG_LOAD", "MAX_LOAD",
            "AVG_LATENCY_PER_REQ", "AVG_TPS"),
    },
    "tacacs-activity": {
        "tables": {
            "authentication": "TACACS_AUTHENTICATION_LAST_TWO_DAYS",
            "authorization": "TACACS_AUTHORIZATION_LAST_TWO_DAYS",
            "accounting": "TACACS_ACCOUNTING_LAST_TWO_DAYS",
        },
        "columns": (
            "TIMESTAMP", "EPOCH_TIME", "USERNAME", "STATUS", "DEVICE_NAME",
            "AUTHENTICATION_POLICY", "AUTHORIZATION_POLICY", "IDENTITY_STORE",
            "SHELL_PROFILE", "MATCHED_COMMAND_SET", "COMMAND_FROM_DEVICE",
            "COMMAND", "COMMAND_ARGS", "FAILURE_REASON"),
    },
}

DATACONNECT_COMMANDS = set(DATACONNECT_REPORTS) | {
    "dataconnect-schema", "endpoint-fields", "endpoints"}
REST_OPTIONAL_COMMANDS = DATACONNECT_COMMANDS | {"health", "schema"}

ENDPOINT_CONTEXT_SOURCES = {
    "endpoint": {
        "table": "ENDPOINTS_DATA", "mac": ("MAC_ADDRESS",),
        "timestamp": ("UPDATE_TIME", "CREATE_TIME"),
    },
    "auth": {
        "table": "RADIUS_AUTHENTICATIONS",
        "mac": ("CALLING_STATION_ID", "ORIG_CALLING_STATION_ID",
                "ENDPOINT_MAC_ADDRESS", "MAC_ADDRESS"),
        "timestamp": ("TIMESTAMP", "LOGGED_AT"),
    },
    "accounting": {
        "table": "RADIUS_ACCOUNTING",
        "mac": ("CALLING_STATION_ID", "ENDPOINT_MAC_ADDRESS", "MAC_ADDRESS"),
        "timestamp": ("TIMESTAMP", "LOGGED_AT"),
    },
    "error": {
        "table": "RADIUS_ERRORS_VIEW",
        "mac": ("CALLING_STATION_ID", "ENDPOINT_MAC_ADDRESS", "MAC_ADDRESS"),
        "timestamp": ("TIMESTAMP", "LOGGED_AT"),
    },
    "posture": {
        "table": "POSTURE_ASSESSMENT_BY_ENDPOINT",
        "mac": ("ENDPOINT_MAC_ADDRESS", "CALLING_STATION_ID", "MAC_ADDRESS"),
        "timestamp": ("TIMESTAMP", "LOGGED_AT"),
    },
}

ENDPOINT_FIELD_ALIASES = {
    "name": (("endpoint", "HOSTNAME"), ("endpoint", "ASSET_NAME")),
    "hostname": (("endpoint", "HOSTNAME"),),
    "mac": (("endpoint", "MAC_ADDRESS"),),
    "ip": (("endpoint", "ENDPOINT_IP"), ("auth", "FRAMED_IP_ADDRESS")),
    "endpoint-policy": (("endpoint", "ENDPOINT_POLICY"),),
    "profile": (("endpoint", "ENDPOINT_PROFILE"), ("endpoint", "ENDPOINT_POLICY")),
    "identity-group": (("endpoint", "IDENTITY_GROUP"),
                       ("endpoint", "IDENTITY_GROUP_ID"),
                       ("auth", "IDENTITY_GROUP"),
                       ("accounting", "IDENTITY_GROUP")),
    "portal-user": (("endpoint", "PORTAL_USER"),),
    "posture-applicable": (("endpoint", "POSTURE_APPLICABLE"),),
    "profile-server": (("endpoint", "PROFILE_SERVER"),),
    "custom-attributes": (("endpoint", "CUSTOM_ATTRIBUTES"),),
    "probe-data": (("endpoint", "PROBE_DATA"),),
    "authorization-policy": (("auth", "AUTHORIZATION_POLICY"),
                             ("accounting", "AUTHORIZATION_POLICY")),
    "authorization-profile": (("auth", "AUTHORIZATION_PROFILES"),),
    "authorization-rule": (("auth", "AUTHORIZATION_RULE"),),
    "authentication-policy": (("auth", "AUTHENTICATION_POLICY"),),
    "policy-set": (("auth", "POLICY_SET_NAME"),),
    "authentication-method": (("auth", "AUTHENTICATION_METHOD"),),
    "authentication-protocol": (("auth", "AUTHENTICATION_PROTOCOL"),),
    "location": (("auth", "LOCATION"), ("auth", "NETWORK_DEVICE_LOCATION"),
                 ("auth", "NETWORK_DEVICE_GROUPS"),
                 ("accounting", "LOCATION"),
                 ("accounting", "NETWORK_DEVICE_LOCATION"),
                 ("posture", "NAD_LOCATION")),
    "nad": (("auth", "DEVICE_NAME"), ("auth", "NETWORK_DEVICE_NAME"),
            ("accounting", "DEVICE_NAME"), ("error", "NETWORK_DEVICE_NAME")),
    "username": (("auth", "USERNAME"), ("accounting", "USERNAME"),
                 ("error", "USERNAME")),
    "identity-store": (("auth", "IDENTITY_STORE"),
                       ("accounting", "IDENTITY_STORE")),
    "failure-reason": (("auth", "FAILURE_REASON"),
                       ("error", "FAILURE_REASON"),
                       ("posture", "FAILURE_REASON")),
    "ssid": (("auth", "SSID"), ("accounting", "SSID")),
    "nas-ip": (("auth", "NAS_IP_ADDRESS"), ("accounting", "NAS_IP_ADDRESS")),
    "psn": (("auth", "ISE_NODE"), ("accounting", "ISE_NODE"),
            ("error", "ISE_NODE"), ("posture", "ISE_NODE")),
    "posture-status": (("posture", "POSTURE_STATUS"),
                       ("posture", "POLICY_STATUS")),
    "posture-policy": (("posture", "POSTURE_POLICY_MATCHED"),
                       ("posture", "POLICY")),
    "posture-report": (("posture", "POSTURE_REPORT"),),
    "agent-version": (("posture", "POSTURE_AGENT_VERSION"),),
    "endpoint-profile": (("endpoint", "ENDPOINT_POLICY"),
                         ("auth", "ENDPOINT_PROFILE")),
    "device-type": (("auth", "DEVICE_TYPE"),),
    "device-groups": (("auth", "NETWORK_DEVICE_GROUPS"),
                      ("accounting", "DEVICE_GROUPS")),
    "mdm-server": (("auth", "MDM_SERVER_NAME"),),
    "security-group": (("auth", "SECURITY_GROUP"),
                       ("accounting", "SECURITY_GROUP")),
    "response-time": (("auth", "RESPONSE_TIME"),
                      ("accounting", "RESPONSE_TIME"),
                      ("posture", "RESPONSE_TIME")),
}

COMPLETION_LIMIT = 25
COMPLETION_CACHE_TTL = 300.0
COMPLETION_MIN_LIVE_PREFIX = 2
ENDPOINT_SEARCH_CANDIDATE_LIMIT = 5000
_SAFE_LIVE_COMPLETION_TABLES = frozenset(("ENDPOINTS_DATA", "USER_TAB_COLUMNS"))

COMPLETION_STATUS_VALUES = {
    "radius-auth": ("failed", "passed", "success"),
    "posture": ("Compliant", "NonCompliant", "NotApplicable", "Unknown"),
}

COMPLETION_FILTER_FIELDS = {
    "endpoints": ("mac.EQ.", "name.EQ.", "groupId.EQ.", "profileId.EQ."),
    "nads": ("name.EQ.", "ipaddress.EQ.", "NetworkDeviceGroup.EQ."),
    "profiles": ("name.EQ.",),
    "tacacs-users": ("name.EQ.", "identityGroup.EQ."),
    "identity-groups": ("name.EQ.",),
    "network-device-groups": ("name.EQ.",),
}


class CLIError(RuntimeError):
    pass


def _add_output_args(parser):
    parser.add_argument("-o", "--output", choices=("table", "json", "jsonl", "csv"),
                        default="table", help="output format (default: table)")
    parser.add_argument("--select", metavar="FIELDS",
                        help="comma-separated fields to retain")


def build_parser(*, require_command=False):
    parser = argparse.ArgumentParser(
        prog="ise-cli",
        description="Read-only Cisco ISE operator CLI (ERS, OpenAPI, Data Connect, MnT)",
    )
    parser.add_argument("--env-file", help="dotenv file to load after ./.env")
    parser.add_argument(
        "--version", action="version", version=version_string("%(prog)s"))
    subs = parser.add_subparsers(dest="command", required=require_command)

    def command(name, help_text):
        sub = subs.add_parser(name, help=help_text)
        _add_output_args(sub)
        return sub

    def expensive(sub):
        sub.add_argument(
            "--allow-expensive", action="store_true",
            help="explicitly allow a broad production query or complete enumeration")

    def active_scan(sub):
        sub.add_argument(
            "--allow-active-list-scan", action="store_true",
            help="allow MnT ActiveList fallback when direct endpoint resolution fails")

    command("health", "check PAN/ERS, MnT, and Data Connect reachability and authentication")
    command("nodes", "list deployment nodes")

    for name, help_text in (
        ("endpoints", "list endpoints from ERS"),
        ("nads", "list network access devices from ERS"),
        ("profiles", "list profiler profiles from ERS"),
        ("tacacs-users", "list internal users used by Device Administration"),
        ("identity-groups", "list endpoint identity groups from ERS"),
        ("network-device-groups", "list network device groups from ERS"),
    ):
        sub = command(name, help_text)
        sub.add_argument("--limit", type=int, default=100,
                         help="maximum rows (default: 100)")
        sub.add_argument("--all", action="store_true",
                         help="explicitly enumerate every result")
        expensive(sub)
        sub.add_argument("--filter", action="append", default=[],
                         help="ISE ERS filter expression; repeatable")
        if name == "endpoints":
            sub.add_argument(
                "criteria", nargs="*", metavar="[FIELD=]PATTERN",
                help="friendly searches, e.g. LAB-* authorization-policy=Permit*")

    sub = command("endpoint-fields", "list searchable endpoint/context fields")
    sub.add_argument("pattern", nargs="?", help="optional field-name wildcard")

    sub = command("sessions", "list active MnT sessions")
    sub.add_argument("--limit", type=int, default=100)
    sub.add_argument("--all", action="store_true")
    expensive(sub)

    sub = command("endpoint", "inspect an endpoint by MAC, IP, hostname, or ERS id")
    sub.add_argument("identifier")
    sub.add_argument("--id", action="store_true", help="identifier is an ERS endpoint id")
    sub.add_argument("--include-session", action="store_true",
                     help="also query MnT Session/MACAddress")
    active_scan(sub)

    sub = command("resolve", "resolve a MAC, IP, hostname, or ERS id")
    sub.add_argument("identifier")
    sub.add_argument("--id", action="store_true", help="identifier is an ERS endpoint id")
    active_scan(sub)

    sub = command("session", "inspect an active session by MAC, IP, hostname, or ERS id")
    sub.add_argument("identifier")
    active_scan(sub)

    sub = command("auth-status", "show recent authentication status for an endpoint")
    sub.add_argument("identifier")
    sub.add_argument("--seconds", type=int, default=600)
    sub.add_argument("--limit", type=int, default=20)
    expensive(sub)
    active_scan(sub)

    sub = command("secure-client", "inspect Secure Client posture attributes for an endpoint")
    sub.add_argument("identifier")
    sub.add_argument("--include-all", action="store_true",
                     help="include every parsed other_attr_string field")
    active_scan(sub)

    for name, help_text in (
        ("licenses", "show Smart Licensing tier state"),
        ("patches", "show installed ISE patches"),
        ("backup-status", "show the last configuration-backup status"),
        ("repositories", "list configured repositories"),
        ("network-policy-sets", "list Network Access policy sets"),
        ("device-admin-policy-sets", "list Device Administration policy sets"),
        ("authorization-profiles", "list Network Access authorization profiles"),
        ("tacacs-command-sets", "list Device Administration command sets"),
        ("tacacs-shell-profiles", "list Device Administration shell profiles"),
    ):
        command(name, help_text)

    sub = command("certificates", "list system and trusted certificates")
    sub.add_argument("--node", help="limit system certificates to one ISE node hostname")
    sub.add_argument("--trusted-only", action="store_true")
    sub.add_argument("--system-only", action="store_true")

    def report(name, help_text):
        sub = command(name, help_text)
        sub.add_argument("--limit", type=int, default=100,
                         help="maximum rows (default: 100)")
        expensive(sub)
        return sub

    sub = report("radius-auth", "query recent RADIUS authentications from Data Connect")
    sub.add_argument("--identifier", help="endpoint MAC, IP, hostname, or ERS id")
    sub.add_argument("--username")
    sub.add_argument("--nad")
    sub.add_argument("--status")

    sub = report("endpoint-report", "query endpoint inventory from Data Connect")
    sub.add_argument("--identifier", help="endpoint MAC, IP, hostname, or ERS id")
    sub.add_argument("--profile")

    sub = report("radius-errors", "query recent RADIUS failures from Data Connect")
    sub.add_argument("--identifier", help="endpoint MAC, IP, hostname, or ERS id")
    sub.add_argument("--nad")
    sub.add_argument("--message-code")

    sub = report("radius-accounting", "query recent RADIUS accounting from Data Connect")
    sub.add_argument("--identifier", help="endpoint MAC, IP, hostname, or ERS id")
    sub.add_argument("--username")
    sub.add_argument("--nad")

    sub = report("posture", "query recent posture assessments from Data Connect")
    sub.add_argument("--identifier", help="endpoint MAC, IP, hostname, or ERS id")
    sub.add_argument("--status")
    sub.add_argument("--conditions", action="store_true",
                     help="query condition-level rather than endpoint-level assessments")

    sub = report("psn-metrics", "query recent PSN key-performance metrics from Data Connect")
    sub.add_argument("--psn")

    sub = report("tacacs-activity", "query recent TACACS activity from Data Connect")
    sub.add_argument("--username")
    sub.add_argument("--device")
    sub.add_argument("--event-type", choices=("authentication", "authorization", "accounting"),
                     default="authentication")

    sub = command("dataconnect-schema", "show Data Connect reporting-view columns")
    sub.add_argument("table", nargs="?", help="optional reporting view name")

    sub = command("schema", "show command API routes and response contract")
    sub.add_argument("name", nargs="?", choices=tuple(COMMAND_SCHEMAS))

    sub = command("get", "perform an explicit read-only GET against an API family")
    sub.add_argument("family", choices=("ers", "openapi", "mnt"))
    sub.add_argument("path", help="family-relative path beginning with /")
    sub.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    sub.add_argument("--all", action="store_true", help="follow ERS pagination")
    expensive(sub)
    sub.add_argument("--no-unwrap", action="store_true",
                     help="keep the OpenAPI response envelope")
    return parser


def _load_config(env_file=None, *, require_rest=True):
    load_dotenv(interpolate=False)
    deployed = env_file or os.environ.get(
        "ISE_EXPORTER_ENV_FILE", "/etc/ise-exporter/ise-exporter.env")
    if deployed and os.path.isfile(deployed):
        load_dotenv(deployed, interpolate=False)
    cfg = Config.from_env()
    if (require_rest
            and (not cfg.ise_host or not cfg.ise_mnt_host
                 or not cfg.ise_user or not cfg.ise_pass)):
        raise CLIError("ISE_HOST, ISE_MNT_HOST, ISE_USER, and ISE_PASS are required")
    return cfg


def _rest_ready(cfg):
    return bool(cfg and cfg.ise_host and cfg.ise_mnt_host and cfg.ise_user and cfg.ise_pass)


def _require_expensive(args, cfg, reason):
    production_safe = getattr(cfg, "cli_production_safe", True)
    globally_allowed = getattr(cfg, "cli_allow_expensive", False)
    explicitly_allowed = getattr(args, "allow_expensive", False)
    if production_safe and not (globally_allowed or explicitly_allowed):
        raise CLIError(
            f"{reason}; rerun with --allow-expensive after confirming production impact")


def _guard_row_limit(args, cfg):
    maximum = int(getattr(cfg, "cli_max_rows", 1000))
    if getattr(args, "limit", 0) > maximum:
        _require_expensive(args, cfg, f"--limit above the production-safe maximum {maximum}")


def _leading_wildcard(pattern):
    return str(pattern).startswith(("*", "?"))


def _params(items):
    result = {}
    for item in items:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise CLIError(f"invalid --param {item!r}; expected KEY=VALUE")
        result[key] = value
    return result


def _ers_rows(client, path, *, limit=100, all_rows=False, filters=()):
    if limit < 1:
        raise CLIError("--limit must be at least 1")
    rows = []
    page = 1
    while all_rows or len(rows) < limit:
        if page > ERS_MAX_PAGES:
            raise CLIError(
                f"ERS inventory exceeded the production safety ceiling of "
                f"{ERS_MAX_PAGES * 100:,} rows")
        size = 100 if all_rows else min(100, limit - len(rows))
        params = {"size": size, "page": page}
        if filters:
            params["filter"] = filters if len(filters) > 1 else filters[0]
        batch = client.get_ers(path, params, api_name=f"cli_{path.rsplit('/', 1)[-1]}")
        if batch is None:
            raise CLIError(f"ISE returned no response for ERS {path}")
        if not isinstance(batch, list):
            return batch
        rows.extend(batch)
        if len(batch) < size:
            break
        page += 1
    return rows if all_rows else rows[:limit]


def _endpoint_detail_by_id(client, endpoint_id):
    raw = client.get_ers(f"/config/endpoint/{endpoint_id}", api_name="cli_endpoint_detail")
    if raw is None:
        raise CLIError(f"endpoint detail unavailable for {endpoint_id}")
    return raw.get("ERSEndPoint", raw) if isinstance(raw, dict) else raw


def _identifier_kind(identifier, by_id=False):
    value = str(identifier).strip()
    if by_id or re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
        return "id"
    if is_mac(value):
        return "mac"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "hostname"


def _response_rows(value):
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("items", "resources", "endpoints", "data"):
        rows = value.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return [value]


def _field(record, *names):
    wanted = {re.sub(r"[^a-z0-9]", "", name.lower()) for name in names}
    for key, value in record.items():
        normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
        if normalized in wanted and value not in (None, ""):
            return str(value).strip()
    return ""


def _dataconnect_endpoint_candidates(dataconnect, identifier, kind):
    if dataconnect is None or kind not in ("ip", "hostname"):
        return []
    comparison = ("endpoint_ip = :identifier" if kind == "ip"
                  else "LOWER(hostname) = LOWER(:identifier)")
    return dataconnect.query(f"""
        SELECT id, endpoint_id, mac_address, endpoint_ip, hostname,
               endpoint_policy, identity_group_id
        FROM endpoints_data
        WHERE {comparison}
        ORDER BY update_time DESC NULLS LAST
        FETCH FIRST 10 ROWS ONLY
    """, {"identifier": identifier})


def _session_mac(session):
    for name in ("calling_station_id", "callingStationId", "mac_address", "mac"):
        value = _field(session, name)
        if is_mac(value):
            return normalize_mac(value)
    return ""


def _session_matches(session, identifier, kind):
    if kind == "ip":
        values = (_field(session, "framed_ip_address"), _field(session, "ip_address"),
                  _field(session, "endpoint_ip"), _field(session, "framedIpAddress"))
        return identifier in values
    if kind == "hostname":
        wanted = identifier.rstrip(".").casefold()
        values = (_field(session, "hostname"), _field(session, "host_name"),
                  _field(session, "endpoint_name"), _field(session, "system_name"))
        return any(value.rstrip(".").casefold() == wanted for value in values if value)
    return False


def _sessions_for_identifier(client, identifier, kind, *, allow_active_scan=False):
    if kind == "mac":
        return _mnt_sessions(
            client, f"/Session/MACAddress/{normalize_mac(identifier)}", "cli_session_lookup")
    if kind == "ip":
        direct = _mnt_sessions(client, f"/Session/IPAddress/{identifier}", "cli_session_lookup")
        if direct:
            return direct
    if not allow_active_scan:
        raise CLIError(
            "direct MnT lookup did not resolve the endpoint; ActiveList fallback is disabled "
            "in production mode (use --allow-active-list-scan to request it explicitly)")
    active = _mnt_sessions(client, "/Session/ActiveList", "cli_session_resolve")
    return [session for session in active if _session_matches(session, identifier, kind)]


def _resolve_endpoint(client, identifier, by_id=False, dataconnect=None,
                      *, allow_active_scan=False):
    original = str(identifier).strip()
    kind = _identifier_kind(original, by_id)
    endpoint = None
    sessions = []
    mac = ""
    endpoint_id = ""
    source = ""
    resolved_ip = ""
    resolved_hostname = ""
    candidates = []
    dataconnect_error = None

    if kind == "id":
        endpoint_id = original
        endpoint = _endpoint_detail_by_id(client, endpoint_id)
        source = "ers"
    elif kind == "mac":
        mac = normalize_mac(original)
        matches = client.get_ers(
            "/config/endpoint", {"size": 2, "filter": f"mac.EQ.{mac}"},
            api_name="cli_endpoint_lookup",
        )
        if matches:
            endpoint_id = _field(matches[0], "id")
            endpoint = (_endpoint_detail_by_id(client, endpoint_id)
                        if endpoint_id else matches[0])
            source = "ers"
        else:
            sessions = _sessions_for_identifier(
                client, mac, kind, allow_active_scan=allow_active_scan)
            source = "mnt" if sessions else "input"
    else:
        try:
            dc_candidates = _dataconnect_endpoint_candidates(dataconnect, original, kind)
        except Exception as error:
            dataconnect_error = error
            dc_candidates = []
        candidates = dc_candidates
        if candidates:
            candidate = candidates[0]
            resolved_ip = _field(candidate, "ipAddress", "endpoint_ip")
            resolved_hostname = _field(candidate, "assetName", "hostname")
            # ENDPOINTS_DATA.ID is the ERS endpoint UUID. ENDPOINT_ID is ISE's
            # separate profiling identity (usually prefixed with ``epid:``).
            endpoint_id = str(candidate.get("id") or "")
            mac_value = (_field(candidate, "mac", "mac_address")
                         or _field(candidate, "name"))
            mac = normalize_mac(mac_value) if is_mac(mac_value) else ""
            try:
                endpoint = (_endpoint_detail_by_id(client, endpoint_id)
                            if endpoint_id else candidate)
            except CLIError:
                endpoint = candidate
            source = "dataconnect"
            if dc_candidates and endpoint is not candidate:
                source = "dataconnect+ers"
        if not mac:
            try:
                sessions = _sessions_for_identifier(
                    client, original, kind, allow_active_scan=allow_active_scan)
            except CLIError as error:
                if dataconnect_error is not None:
                    raise CLIError(
                        f"Data Connect endpoint resolution failed: {dataconnect_error}; "
                        f"MnT fallback also failed: {error}") from dataconnect_error
                raise
            mac = _session_mac(sessions[0]) if sessions else ""
        if not mac and kind == "hostname":
            try:
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(original, None)})
            except socket.gaierror:
                addresses = []
            for address in addresses:
                ip_sessions = _sessions_for_identifier(
                    client, address, "ip", allow_active_scan=allow_active_scan)
                if ip_sessions:
                    sessions = ip_sessions
                    mac = _session_mac(ip_sessions[0])
                    break
        if endpoint is None and mac:
            matches = client.get_ers(
                "/config/endpoint", {"size": 2, "filter": f"mac.EQ.{mac}"},
                api_name="cli_endpoint_lookup",
            )
            if matches:
                endpoint_id = _field(matches[0], "id")
                endpoint = (_endpoint_detail_by_id(client, endpoint_id)
                            if endpoint_id else matches[0])
                source = "mnt+ers"

    if endpoint is not None:
        endpoint_mac = _field(endpoint, "mac") or _field(endpoint, "name")
        if not mac and is_mac(endpoint_mac):
            mac = normalize_mac(endpoint_mac)
        endpoint_id = endpoint_id or _field(endpoint, "id")
    if endpoint is None and not sessions:
        if dataconnect_error is not None:
            raise CLIError(
                f"Data Connect endpoint resolution failed: {dataconnect_error}") \
                from dataconnect_error
        raise CLIError(f"endpoint not found for {kind} {original!r}")

    return {
        "input": original,
        "kind": kind,
        "source": source or ("mnt" if sessions else "unknown"),
        "candidate_count": len(candidates) if candidates else (1 if endpoint else 0),
        "ambiguous": len(candidates) > 1,
        "mac": mac,
        "ip": original if kind == "ip" else (
            resolved_ip or _field(endpoint or {}, "ipAddress", "endpoint_ip")),
        "hostname": original if kind == "hostname" else (
            resolved_hostname or _field(endpoint or {}, "assetName", "hostname")),
        "endpoint_id": endpoint_id,
        "endpoint": endpoint,
        "sessions": sessions,
    }


def _resolved_mac(client, identifier, dataconnect=None, *, allow_active_scan=False):
    if is_mac(identifier):
        return normalize_mac(identifier)
    resolved = _resolve_endpoint(
        client, identifier, dataconnect=dataconnect,
        allow_active_scan=allow_active_scan)
    if resolved["ambiguous"]:
        raise CLIError(
            f"{identifier!r} matches {resolved['candidate_count']} endpoint records; "
            "run resolve to inspect them, then use an exact MAC address or ERS id")
    if not resolved["mac"]:
        raise CLIError(f"could not resolve {identifier!r} to a MAC address")
    return resolved["mac"]


def _mnt_sessions(client, path, api_name):
    raw = client.get_mnt_xml(path, api_name=api_name)
    if raw is None:
        raise CLIError(f"MnT returned no response for {path}")
    return raw.get("sessions", [])


def _secure_client(client, mac, include_all=False):
    sessions = _mnt_sessions(client, f"/Session/MACAddress/{mac}", "cli_secure_client")
    if not sessions:
        raise CLIError(f"no active MnT session found for {mac}")
    detail = sessions[0]
    other = parse_other_attr_string(detail.get("other_attr_string", ""))
    report = other.get("PostureReport", "")
    result = {
        "mac": mac,
        "posture_status": normalize_posture(
            other.get("PostureStatus") or detail.get("posture_status")
            or other.get("PostureAssessmentStatus")),
        "posture_applicable": other.get("PostureApplicable", ""),
        "assessment_status": other.get("PostureAssessmentStatus", ""),
        "agent_version": normalize_agent_version(first_nonempty(
            other, "PostureAgentVersion", "SecureClientVersion", "AnyConnectVersion")),
        "policies": [{"policy": policy, "result": policy_result}
                     for policy, policy_result in parse_posture_report(report)],
    }
    if include_all:
        result["other_attributes"] = other
    return result


def _dataconnect_table_columns(dataconnect, table):
    return table_columns(dataconnect, table)


def _first_column(columns, *candidates):
    available = set(columns)
    return next((candidate for candidate in candidates if candidate in available), "")


def _field_alias(value):
    return re.sub(r"[^a-z0-9]+", "-", str(value).strip().casefold()).strip("-")


def _searchable_datatype(data_type):
    value = str(data_type).upper()
    return any(token in value for token in (
        "CHAR", "CLOB", "NUMBER", "INTEGER", "FLOAT", "DECIMAL", "DATE", "TIMESTAMP"))


def _endpoint_field_bindings(dataconnect, *, query=None):
    """Discover searchable endpoint/context fields from the live ISE schema."""
    if dataconnect is None:
        raise CLIError("endpoint field search requires configured Data Connect credentials")
    tables = tuple(dict.fromkeys(
        spec["table"] for spec in ENDPOINT_CONTEXT_SOURCES.values()))
    try:
        # One catalog statement covers every fixed Patch 11 context view. At a
        # deliberately tiny database duty cycle, issuing one query per view
        # would multiply adaptive cooldown without providing fresher metadata.
        metadata = metadata_rows(dataconnect, tables, query=query)
        if metadata is None:
            raise CLIError("Data Connect pacing gate is busy")
        schemas_by_table = schema_by_table(metadata)
    except Exception as error:
        raise CLIError(f"Data Connect endpoint schema lookup failed: {error}") from error

    schemas = {}
    for source, spec in ENDPOINT_CONTEXT_SOURCES.items():
        schemas[source] = schemas_by_table.get(spec["table"], {})
        if source == "endpoint" and not schemas[source]:
            raise CLIError(
                f"Data Connect schema lookup failed for {spec['table']}: view unavailable")
        if (source != "endpoint" and not _first_column(
                schemas[source], *spec["mac"])):
            # A view without an endpoint correlation key cannot safely participate
            # in an endpoint search, so do not advertise its fields as searchable.
            schemas[source] = {}

    bindings = {}
    rows = []
    for source, columns in schemas.items():
        table = ENDPOINT_CONTEXT_SOURCES[source]["table"]
        for column, data_type in columns.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_$#]*", column):
                continue
            if not _searchable_datatype(data_type):
                continue
            short = _field_alias(column)
            qualified = f"{source}.{short}"
            binding = {"source": source, "table": table, "column": column,
                       "data_type": data_type, "field": qualified}
            bindings.setdefault(qualified, []).append(binding)
            bindings.setdefault(short, []).append(binding)
            rows.append({"field": qualified, "short_field": short, "source": source,
                         "view": table, "column": column, "data_type": data_type})

    for alias, candidates in ENDPOINT_FIELD_ALIASES.items():
        resolved = []
        for source, column in candidates:
            data_type = schemas.get(source, {}).get(column)
            if data_type and _searchable_datatype(data_type):
                resolved.append({
                    "source": source, "table": ENDPOINT_CONTEXT_SOURCES[source]["table"],
                    "column": column, "data_type": data_type, "field": alias})
        if resolved:
            bindings[alias] = resolved
    return bindings, rows, schemas


def _endpoint_fields(dataconnect, pattern=None, *, query=None):
    bindings, rows, _schemas = _endpoint_field_bindings(dataconnect, query=query)
    aliases = set(ENDPOINT_FIELD_ALIASES) & set(bindings)
    for row in rows:
        short = row["short_field"]
        if len(bindings.get(short, ())) == 1:
            aliases.add(short)
    result = []
    for alias in sorted(aliases, key=str.casefold):
        sources = bindings[alias]
        result.append({
            "field": alias,
            "qualified_fields": sorted({item["field"] for item in sources}),
            "sources": sorted({item["source"] for item in sources}),
            "views": sorted({item["table"] for item in sources}),
            "columns": sorted({item["column"] for item in sources}),
            "data_types": sorted({item["data_type"] for item in sources}),
        })
    result.extend({
        "field": row["field"], "qualified_fields": [row["field"]],
        "sources": [row["source"]], "views": [row["view"]],
        "columns": [row["column"]], "data_types": [row["data_type"]],
    } for row in rows)
    if pattern:
        regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$", re.I)
        result = [row for row in result if regex.match(row["field"])]
    unique = {row["field"]: row for row in result}
    return [unique[field] for field in sorted(unique, key=str.casefold)]


def _parse_endpoint_criteria(items):
    criteria = []
    for item in items:
        field, separator, pattern = str(item).partition("=")
        if not separator:
            field, pattern = "name", field
        field = (_field_alias(field) if "." not in field else
                 ".".join(_field_alias(part) for part in field.split(".", 1)))
        if not field or not pattern:
            raise CLIError(
                f"invalid endpoint search {item!r}; use FIELD=PATTERN, e.g. location=Berlin-*")
        criteria.append((field, pattern))
    return criteria


def _sql_pattern(pattern):
    escaped = (str(pattern).replace("\\", "\\\\").replace("%", "\\%")
               .replace("_", "\\_").replace("*", "%").replace("?", "_"))
    return escaped.upper()


def _text_expression(alias, column, data_type):
    if any(token in data_type for token in ("NUMBER", "INTEGER", "FLOAT", "DECIMAL")):
        return f"TO_CHAR({alias}.{column})"
    if "DATE" in data_type or "TIMESTAMP" in data_type:
        return f"TO_CHAR({alias}.{column}, 'YYYY-MM-DD HH24:MI:SS')"
    return f"{alias}.{column}"


def _normalized_mac_expression(alias, column):
    """Normalize a bounded context-side MAC without wrapping the inventory join key."""
    reference = f"{alias}.{column}"
    return (
        f"UPPER(REPLACE(REPLACE(REPLACE(TRIM({reference}), ':', ''), '-', ''), '.', ''))"
    )


def _mac_join_predicate(endpoint_reference, normalized_reference):
    """Match Cisco MAC renderings while keeping ENDPOINTS_DATA.MAC_ADDRESS indexable."""
    compact = normalized_reference
    colon = " || ':' || ".join(
        f"SUBSTR({compact}, {offset}, 2)" for offset in range(1, 12, 2))
    hyphen = " || '-' || ".join(
        f"SUBSTR({compact}, {offset}, 2)" for offset in range(1, 12, 2))
    dotted = " || '.' || ".join(
        f"SUBSTR({compact}, {offset}, 4)" for offset in range(1, 10, 4))
    variants = (compact, f"LOWER({compact})", colon, f"LOWER({colon})",
                hyphen, f"LOWER({hyphen})", dotted, f"LOWER({dotted})")
    return f"{endpoint_reference} IN ({', '.join(variants)})"


def _safe_select_expression(alias, column, data_type):
    """Project ISE reporting values without trusting legacy text encoding.

    Some ISE 3.3 ENDPOINTS_DATA VARCHAR2 values contain historical probe or
    custom-attribute bytes that python-oracledb cannot decode as UTF-8. ASCIISTR
    makes Oracle return an ASCII-only representation while preserving escaped
    non-ASCII code points. The conversion happens before bytes reach the driver,
    so one malformed optional attribute cannot make an entire endpoint search
    unusable.
    """
    normalized = str(data_type).upper()
    reference = f"{alias}.{column}"
    if "CLOB" in normalized:
        return f"ASCIISTR(DBMS_LOB.SUBSTR({reference}, 4000, 1)) AS {column}"
    if "CHAR" in normalized:
        return f"ASCIISTR({reference}) AS {column}"
    if "TIMESTAMP" in normalized and "TIME ZONE" in normalized:
        return f"TO_CHAR({reference}, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF TZH:TZM') AS {column}"
    if "TIMESTAMP" in normalized:
        return f"TO_CHAR({reference}, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF') AS {column}"
    if "DATE" in normalized:
        return f"TO_CHAR({reference}, 'YYYY-MM-DD\"T\"HH24:MI:SS') AS {column}"
    return f"{reference}"


def _safe_match_expression(alias, column, data_type):
    normalized = str(data_type).upper()
    if "CLOB" in normalized:
        return f"ASCIISTR(DBMS_LOB.SUBSTR({alias}.{column}, 4000, 1))"
    if "CHAR" in normalized:
        return f"ASCIISTR({alias}.{column})"
    return _text_expression(alias, column, normalized)


def _decode_endpoint_attribute_payload(value):
    """Turn ISE endpoint attribute blobs into operator-readable structures."""
    if not isinstance(value, str) or not value:
        return value
    stripped = value.strip()
    if stripped[:1] in ("{", "["):
        try:
            return json.loads(stripped)
        except (TypeError, ValueError):
            pass

    # PROBE_DATA on ISE 3.3 is commonly a one-byte-length-prefixed key/value
    # stream: header, 0x11 separator, length, text, separator, length, text...
    # Parse it only when the complete framing is internally consistent. Unknown
    # payloads stay verbatim so the CLI never discards diagnostic evidence.
    if len(value) < 3 or value[1] != "\x11":
        return value
    position = 2
    tokens = []
    while position < len(value):
        length = ord(value[position])
        position += 1
        if position + length > len(value):
            return value
        tokens.append(value[position:position + length])
        position += length
        if position == len(value):
            break
        if value[position] != "\x11":
            return value
        position += 1
    if len(tokens) < 2:
        return value
    if len(tokens) % 2:
        tokens.append("")
    return {tokens[index]: tokens[index + 1] for index in range(0, len(tokens), 2)}


def _normalize_endpoint_payloads(rows):
    for row in rows:
        for field in ("custom_attributes", "probe_data"):
            if field in row:
                row[field] = _decode_endpoint_attribute_payload(row[field])
    return rows


def _dataconnect_endpoint_search(
        dataconnect, criteria, limit, all_rows=False, window_hours=6):
    if limit < 1 or limit > 5000:
        raise CLIError("--limit must be between 1 and 5000")
    bindings, _rows, schemas = _endpoint_field_bindings(dataconnect)
    endpoint_columns = schemas.get("endpoint", {})
    endpoint_mac = _first_column(endpoint_columns, *ENDPOINT_CONTEXT_SOURCES["endpoint"]["mac"])
    if not endpoint_columns or not endpoint_mac:
        raise CLIError("Data Connect ENDPOINTS_DATA lacks a searchable MAC column")

    grouped = {}
    for field, pattern in criteria:
        options = bindings.get(field, ())
        if not options:
            suggestions = sorted(name for name in bindings if name.startswith(field[:3]))[:5]
            suffix = f"; try: {', '.join(suggestions)}" if suggestions else \
                "; run endpoint-fields to list available fields"
            raise CLIError(f"unknown or unavailable endpoint field {field!r}{suffix}")
        grouped.setdefault(field, []).append((pattern, options))

    parameters = {}
    common_table_expressions = []
    joins = []
    matched_context_columns = []
    for field_index, (field, values) in enumerate(grouped.items()):
        branches = []
        for value_index, (pattern, options) in enumerate(values):
            parameter = f"search_{field_index}_{value_index}"
            parameters[parameter] = _sql_pattern(pattern)
            for option_index, binding in enumerate(options):
                source = binding["source"]
                source_columns = schemas.get(source, {})
                source_mac = _first_column(
                    source_columns, *ENDPOINT_CONTEXT_SOURCES[source]["mac"])
                if not source_mac:
                    continue
                alias = f"s{field_index}_{value_index}_{option_index}"
                match_value = _safe_match_expression(
                    alias, binding["column"], binding["data_type"])
                match = f"UPPER({match_value}) LIKE :{parameter} ESCAPE '\\'"
                timestamp = _first_column(
                    source_columns, *ENDPOINT_CONTEXT_SOURCES[source]["timestamp"])
                recent = ""
                if source != "endpoint" and timestamp:
                    recent = " AND " + recent_event_predicate(
                        f"{alias}.{timestamp}", window_hours)
                normalized_mac = _normalized_mac_expression(alias, source_mac)
                branches.append(
                    f"SELECT {normalized_mac} AS match_mac, "
                    f"{match_value} AS match_value "
                    f"FROM {binding['table']} {alias} "
                    f"WHERE {alias}.{source_mac} IS NOT NULL{recent} AND {match}")
        if not branches:
            raise CLIError(f"endpoint field {field!r} has no MAC-correlatable source")
        cte = f"matched_{field_index}"
        union = " UNION ".join(dict.fromkeys(branches))
        common_table_expressions.append(
            f"{cte} AS (SELECT match_mac, MIN(match_value) AS match_value "
            f"FROM ({union}) GROUP BY match_mac "
            f"FETCH FIRST {ENDPOINT_SEARCH_CANDIDATE_LIMIT} ROWS ONLY)")
        joins.append(
            f"JOIN {cte} m{field_index} ON "
            f"{_mac_join_predicate(f'e.{endpoint_mac}', f'm{field_index}.match_mac')}")
        context_alias = f"MATCHED_CONTEXT_{field_index}"
        matched_context_columns.append((field, context_alias))

    select_expressions = [
        _safe_select_expression("e", column, data_type)
        for column, data_type in endpoint_columns.items() if _searchable_datatype(data_type)
    ]
    select_expressions.extend(
        f"m{index}.match_value AS {alias}"
        for index, (_field, alias) in enumerate(matched_context_columns)
    )
    order_column = _first_column(endpoint_columns, "UPDATE_TIME", "CREATE_TIME", "HOSTNAME")
    order = f" ORDER BY e.{order_column} DESC NULLS LAST" if order_column else ""
    result_limit = ENDPOINT_SEARCH_CANDIDATE_LIMIT if all_rows else limit
    sql = (
        f"WITH {', '.join(common_table_expressions)} "
        f"SELECT {', '.join(select_expressions)} FROM ENDPOINTS_DATA e "
        f"{' '.join(joins)}{order} FETCH FIRST {result_limit} ROWS ONLY")
    try:
        result = dataconnect.query(sql, parameters)
    except Exception as error:
        raise CLIError(f"Data Connect endpoint search failed: {error}") from error
    for row in result:
        row["matched_filters"] = [f"{field}={pattern}" for field, pattern in criteria]
        matched_context = {}
        for field, alias in matched_context_columns:
            value = row.pop(alias.lower(), None)
            if value is None:
                value = row.pop(alias, None)
            matched_context[field] = value
        row["matched_context"] = matched_context
    return _normalize_endpoint_payloads(result)


def _dataconnect_report(args, client, dataconnect, cfg):
    if dataconnect is None:
        raise CLIError("this command requires configured Data Connect credentials")
    if args.limit < 1 or args.limit > 5000:
        raise CLIError("--limit must be between 1 and 5000")
    spec = DATACONNECT_REPORTS[args.command]
    table = spec.get("table")
    if args.command == "posture" and args.conditions:
        table = spec["condition_table"]
    elif args.command == "tacacs-activity":
        table = spec["tables"][args.event_type]

    try:
        column_types = _dataconnect_table_columns(dataconnect, table)
    except Exception as error:
        raise CLIError(f"Data Connect schema lookup failed for {table}: {error}") from error
    if not column_types:
        raise CLIError(f"Data Connect view {table} is unavailable")
    columns = list(column_types)
    selected = [column for column in spec["columns"] if column in columns]
    if not selected:
        selected = columns[:20]

    predicates = []
    parameters = {}

    identifier = getattr(args, "identifier", None)
    if identifier:
        kind = _identifier_kind(identifier)
        value = str(identifier).strip()
        if kind == "hostname":
            matches = _dataconnect_endpoint_candidates(dataconnect, value, kind)
            if not matches:
                raise CLIError(f"endpoint not found for hostname {value!r}")
            if len(matches) > 1:
                raise CLIError(
                    f"hostname {value!r} matches {len(matches)} endpoint records; "
                    "use an exact MAC address or ERS id")
            value = _field(matches[0], "mac_address", "mac")
            kind = "mac"
        elif kind == "id":
            if client is None:
                raise CLIError("ERS credentials are required to resolve an endpoint id")
            value = _resolved_mac(client, value, dataconnect)
            kind = "mac"
        if kind == "mac":
            value = normalize_mac(value)
            column = _first_column(
                columns, "CALLING_STATION_ID", "ENDPOINT_MAC_ADDRESS", "MAC_ADDRESS")
        else:
            column = _first_column(
                columns, "FRAMED_IP_ADDRESS", "IP_ADDRESS", "ENDPOINT_IP")
        if not column:
            raise CLIError(f"{table} cannot filter by {kind}")
        predicates.append(f"{column} = :endpoint_identifier")
        parameters["endpoint_identifier"] = value

    simple_filters = (
        ("username", ("USERNAME", "USER_NAME", "IDENTITY")),
        ("nad", ("DEVICE_NAME", "NETWORK_DEVICE_NAME", "NAS_IP_ADDRESS")),
        ("message_code", ("MESSAGE_CODE",)),
        ("psn", ("ISE_NODE",)),
        ("device", ("DEVICE_NAME",)),
        ("profile", ("ENDPOINT_POLICY",)),
    )
    for argument, candidates in simple_filters:
        value = getattr(args, argument, None)
        if value is None:
            continue
        column = _first_column(columns, *candidates)
        if not column:
            raise CLIError(f"{table} cannot filter by --{argument.replace('_', '-')}")
        parameter = f"filter_{argument}"
        predicates.append(f"{column} = :{parameter}")
        parameters[parameter] = value

    status = getattr(args, "status", None)
    if status is not None:
        status_column = _first_column(columns, "STATUS", "POSTURE_STATUS", "POLICY_STATUS")
        if status_column:
            predicates.append(f"LOWER({status_column}) = LOWER(:filter_status)")
            parameters["filter_status"] = status
        elif "FAILED" in columns and status.casefold() in ("failed", "passed"):
            predicates.append("NVL(FAILED, 0) " + ("> 0" if status.casefold() == "failed" else "= 0"))
        else:
            raise CLIError(f"{table} cannot filter by --status")

    timestamp_column = _first_column(columns, "TIMESTAMP", "LOGGED_AT", "LOGGED_TIME")
    epoch_column = _first_column(columns, "EPOCH_TIME")
    if timestamp_column:
        predicates.append(recent_event_predicate(
            timestamp_column, getattr(cfg, "dataconnect_event_window_hours", 6)))
    elif epoch_column:
        window = max(1, min(6, int(getattr(
            cfg, "dataconnect_event_window_hours", 6))))
        predicates.append(f"{epoch_column} >= :minimum_epoch")
        parameters["minimum_epoch"] = int(time.time()) - window * 3600
    order_column = timestamp_column or epoch_column
    where = " WHERE " + " AND ".join(predicates) if predicates else ""
    order = f" ORDER BY {order_column} DESC" if order_column else ""
    select_expressions = [
        (f"TO_CHAR({column}, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF TZH:TZM') AS {column}"
         if "TIME ZONE" in column_types[column] else column)
        for column in selected
    ]
    sql = (f"SELECT {', '.join(select_expressions)} FROM {table}{where}{order} "
           f"FETCH FIRST {args.limit} ROWS ONLY")
    try:
        rows = dataconnect.query(sql, parameters)
        return _normalize_endpoint_payloads(rows) if table == "ENDPOINTS_DATA" else rows
    except Exception as error:
        raise CLIError(f"Data Connect query failed for {table}: {error}") from error


def _dataconnect_health(dataconnect):
    if dataconnect is None:
        return None
    try:
        # Authentication/access proof only: do not count the complete catalog
        # when a single bounded metadata row proves the same thing.
        query_if_ready = getattr(dataconnect, "query_if_ready", None)
        query = query_if_ready if query_if_ready is not None else dataconnect.query
        rows = query("SELECT 1 AS available FROM user_views FETCH FIRST 1 ROWS ONLY")
        if rows is None:
            return {
                "reachable": None,
                "authenticated": None,
                "http_status": 0,
                "probe_status": "deferred",
            }
        healthy = bool(rows)
        return {
            "reachable": healthy,
            "authenticated": healthy,
            "http_status": 0,
            "probe_status": "completed",
        }
    except Exception:
        return {
            "reachable": False,
            "authenticated": False,
            "http_status": 0,
            "probe_status": "completed",
        }


def _dataconnect_schema(dataconnect, table=None):
    if dataconnect is None:
        raise CLIError("this command requires configured Data Connect credentials")
    if not table:
        try:
            # Default discovery is the exporter contract, not the Data Connect
            # account's entire catalog. Operators may still name one custom view.
            return metadata_rows(dataconnect)
        except Exception as error:
            raise CLIError(f"Data Connect schema query failed: {error}") from error
    parameters = {}
    normalized = table.strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", normalized):
        raise CLIError("Data Connect table must contain only letters, numbers, and underscores")
    predicate = " WHERE table_name = :table_name"
    parameters["table_name"] = normalized
    try:
        return dataconnect.query(f"""
            SELECT table_name, column_id, column_name, data_type, data_length, nullable
            FROM user_tab_columns{predicate}
            ORDER BY table_name, column_id
        """, parameters)
    except Exception as error:
        raise CLIError(f"Data Connect schema query failed: {error}") from error


def _execute(args, client, cfg, dataconnect=None):
    command = args.command
    if command == "endpoint-fields":
        return _endpoint_fields(dataconnect, args.pattern)
    if command == "endpoints":
        criteria = _parse_endpoint_criteria(args.criteria)
        _guard_row_limit(args, cfg)
        if args.all:
            _require_expensive(args, cfg, "complete endpoint enumeration is disabled")
            if criteria and dataconnect is not None:
                raise CLIError(
                    "--all cannot truthfully enumerate Data Connect endpoint matches "
                    "within the 5,000-row process safety ceiling; use a narrower "
                    "pattern with --limit instead")
        broad_patterns = [pattern for _field, pattern in criteria
                          if _leading_wildcard(pattern)]
        if broad_patterns:
            _require_expensive(
                args, cfg,
                f"leading-wildcard endpoint search {broad_patterns[0]!r} can scan a large view")
        if any(".CONTAINS." in item.upper() or ".ENDSW." in item.upper()
               for item in args.filter):
            _require_expensive(args, cfg, "broad ERS CONTAINS/ENDSW filter is disabled")
        if criteria and dataconnect is not None:
            if args.filter:
                raise CLIError(
                    "friendly endpoint searches cannot be combined with advanced --filter")
            return _dataconnect_endpoint_search(
                dataconnect, criteria, args.limit, all_rows=args.all,
                window_hours=getattr(cfg, "dataconnect_event_window_hours", 6))
        if criteria:
            raise CLIError(
                "endpoint name and attribute searches require Data Connect on ISE 3.3 "
                "Patch 11 because its ERS endpoint collection rejects name filters; "
                "configure ISE_DATACONNECT_* or list bounded ERS inventory without a pattern")
        else:
            filters = args.filter
        if client is None:
            raise CLIError("plain endpoint inventory requires configured ERS credentials")
        return _ers_rows(client, ERS_INVENTORIES[command], limit=args.limit,
                         all_rows=args.all, filters=filters)
    if command == "health":
        result = []
        if client is not None:
            health = client.health_check()
            for service, host, key in (
                    ("PAN/ERS", cfg.ise_host, "pan"),
                    ("MnT", cfg.ise_mnt_host, "mnt")):
                status = health[key]
                if isinstance(status, dict):
                    result.append({"service": service, "host": host,
                                   "probe_status": "completed", **status})
                else:
                    # Compatibility for injected/test clients using the old bool shape.
                    result.append({"service": service, "host": host,
                                   "reachable": bool(status),
                                   "authenticated": bool(status), "http_status": 0,
                                   "probe_status": "completed"})
        dataconnect_status = _dataconnect_health(dataconnect)
        if dataconnect_status is not None:
            result.append({"service": "Data Connect", "host": cfg.dataconnect_host,
                           **dataconnect_status})
        if not result:
            raise CLIError("no REST/MnT or Data Connect credentials are configured")
        return result
    if command == "nodes":
        result = client.get_pan_api("/deployment/node", api_name="cli_nodes")
        if result is None:
            raise CLIError("ISE returned no deployment-node response")
        return result
    if command in ERS_INVENTORIES:
        _guard_row_limit(args, cfg)
        if args.all:
            _require_expensive(args, cfg, "complete ERS inventory enumeration is disabled")
        return _ers_rows(client, ERS_INVENTORIES[command], limit=args.limit,
                         all_rows=args.all, filters=args.filter)
    if command in OPENAPI_INVENTORIES:
        path, unwrap = OPENAPI_INVENTORIES[command]
        result = client.get_pan_api(path, api_name=f"cli_{command}", unwrap=unwrap)
        if result is None:
            raise CLIError(f"ISE returned no response for {command}")
        return result
    if command in DATACONNECT_REPORTS:
        _guard_row_limit(args, cfg)
        return _dataconnect_report(args, client, dataconnect, cfg)
    if command == "dataconnect-schema":
        return _dataconnect_schema(dataconnect, args.table)
    if command == "sessions":
        _require_expensive(args, cfg, "MnT ActiveList retrieval is disabled")
        if args.limit < 1:
            raise CLIError("--limit must be at least 1")
        rows = _mnt_sessions(client, "/Session/ActiveList", "cli_sessions")
        return rows if args.all else rows[:args.limit]
    if command == "endpoint":
        resolved = _resolve_endpoint(
            client, args.identifier, args.id, dataconnect=dataconnect,
            allow_active_scan=args.allow_active_list_scan)
        detail = resolved["endpoint"]
        if detail is None:
            raise CLIError(f"endpoint detail unavailable for {args.identifier!r}")
        if args.include_session:
            detail = dict(detail)
            mac = resolved["mac"]
            detail["mnt_sessions"] = (resolved["sessions"] or _mnt_sessions(
                client, f"/Session/MACAddress/{mac}", "cli_endpoint_session")) if mac else []
        return detail
    if command == "resolve":
        return _resolve_endpoint(
            client, args.identifier, args.id, dataconnect=dataconnect,
            allow_active_scan=args.allow_active_list_scan)
    if command == "session":
        kind = _identifier_kind(args.identifier)
        if kind in ("mac", "ip"):
            return _sessions_for_identifier(
                client, args.identifier, kind,
                allow_active_scan=args.allow_active_list_scan)
        mac = _resolved_mac(
            client, args.identifier, dataconnect,
            allow_active_scan=args.allow_active_list_scan)
        return _mnt_sessions(client, f"/Session/MACAddress/{mac}", "cli_session")
    if command == "auth-status":
        if args.seconds < 1 or args.limit < 1:
            raise CLIError("--seconds and --limit must be at least 1")
        if args.seconds > AUTH_STATUS_MAX_SECONDS:
            raise CLIError(
                f"--seconds must not exceed the hard production ceiling "
                f"{AUTH_STATUS_MAX_SECONDS}")
        if args.limit > AUTH_STATUS_MAX_LIMIT:
            raise CLIError(
                f"--limit must not exceed the hard production ceiling "
                f"{AUTH_STATUS_MAX_LIMIT}")
        if (args.seconds > AUTH_STATUS_SAFE_SECONDS
                or args.limit > AUTH_STATUS_SAFE_LIMIT):
            _require_expensive(
                args, cfg,
                "auth-status exceeds the production-safe 1-hour/100-result envelope")
        mac = _resolved_mac(
            client, args.identifier, dataconnect,
            allow_active_scan=args.allow_active_list_scan)
        return _mnt_sessions(
            client, f"/AuthStatus/MACAddress/{mac}/{args.seconds}/{args.limit}/All",
            "cli_auth_status",
        )
    if command == "secure-client":
        mac = _resolved_mac(
            client, args.identifier, dataconnect,
            allow_active_scan=args.allow_active_list_scan)
        return _secure_client(client, mac, args.include_all)
    if command == "certificates":
        if args.trusted_only and args.system_only:
            raise CLIError("--trusted-only and --system-only are mutually exclusive")
        rows = []
        if not args.trusted_only:
            nodes = ([{"hostname": args.node}] if args.node else client.get_pan_api(
                "/deployment/node", api_name="cli_certificate_nodes")) or []
            for node in _response_rows(nodes):
                hostname = _field(node, "hostname")
                if not hostname:
                    continue
                certificates = client.get_pan_api(
                    f"/certs/system-certificate/{hostname}", api_name="cli_system_certificates")
                for certificate in _response_rows(certificates):
                    rows.append({"store": "system", "hostname": hostname, **certificate})
        if not args.system_only:
            trusted = client.get_pan_api(
                "/certs/trusted-certificate", api_name="cli_trusted_certificates")
            rows.extend({"store": "trusted", "hostname": "trust_store", **certificate}
                        for certificate in _response_rows(trusted))
        return rows
    if command == "schema":
        return COMMAND_SCHEMAS if args.name is None else COMMAND_SCHEMAS[args.name]
    if command == "get":
        if not args.path.startswith("/") or "://" in args.path or ".." in args.path:
            raise CLIError("path must be family-relative, start with '/', and contain no '..'")
        params = _params(args.param)
        if args.all:
            _require_expensive(args, cfg, "generic ERS pagination is disabled")
        if (args.family == "mnt"
                and args.path.rstrip("/").casefold().endswith("/session/activelist")):
            _require_expensive(args, cfg, "generic MnT ActiveList retrieval is disabled")
        if (args.family == "mnt"
                and args.path.casefold().startswith("/authstatus/")):
            _require_expensive(
                args, cfg,
                "generic MnT AuthStatus retrieval bypasses the bounded auth-status command")
        if args.family == "ers":
            result = client.get_ers(args.path, params or None, get_all=args.all,
                                    api_name="cli_get_ers")
        elif args.family == "openapi":
            result = client.get_pan_api(args.path, api_name="cli_get_openapi",
                                        unwrap=not args.no_unwrap, params=params or None)
        else:
            if params or args.all or args.no_unwrap:
                raise CLIError("MnT get does not accept --param, --all, or --no-unwrap")
            result = client.get_mnt_xml(args.path, api_name="cli_get_mnt")
        if result is None:
            raise CLIError(f"ISE returned no response for {args.family} {args.path}")
        return result
    raise CLIError(f"unknown command {command}")


def _records(value):
    if isinstance(value, list):
        return [item if isinstance(item, dict) else {"value": item} for item in value]
    if isinstance(value, dict):
        return [value]
    return [{"value": value}]


def _project(value, select):
    if not select:
        return value
    fields = [field.strip() for field in select.split(",") if field.strip()]
    if not fields:
        raise CLIError("--select must contain at least one field")
    rows = _records(value)
    return [{field: row.get(field) for field in fields} if isinstance(row, dict)
            else {"value": row} for row in rows]


def _cell(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return str(value)


def _fields(rows):
    result = []
    for row in rows:
        for key in row:
            if key not in result:
                result.append(key)
    return result


def render(value, output="table", select=None, stream=None):
    stream = stream or sys.stdout
    value = _project(value, select)
    if output == "json":
        json.dump(value, stream, indent=2, sort_keys=True, default=str)
        stream.write("\n")
        return
    rows = _records(value)
    if output == "jsonl":
        for row in rows:
            stream.write(json.dumps(
                row, sort_keys=True, separators=(",", ":"), default=str) + "\n")
        return
    fields = _fields(rows)
    if output == "csv":
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows({key: _cell(value) for key, value in row.items()} for row in rows)
        return
    if not rows:
        Console(file=stream, highlight=False).print("[dim]No results.[/dim]")
        return
    console = Console(file=stream, highlight=False)
    if len(rows) == 1:
        # A single ISE object is more readable as a PowerShell-style property list.
        # Nested values get real indentation instead of one truncated JSON cell.
        table = Table.grid(padding=(0, 2), expand=True)
        table.add_column(style="bold cyan", no_wrap=True)
        table.add_column(overflow="fold")
        for field in fields:
            item = rows[0].get(field)
            rendered = (Pretty(item, expand_all=True, indent_guides=True)
                        if isinstance(item, (dict, list)) else Text(_cell(item)))
            table.add_row(field, rendered)
        console.print(table)
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", pad_edge=False,
                  collapse_padding=True)
    for field in fields:
        table.add_column(field, overflow="fold")
    for row in rows:
        table.add_row(*[_cell(row.get(field)) for field in fields])
    console.print(table)


def _subparser(parser, name):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices.get(name)
    return None


class ISEShell(cmd.Cmd):
    intro = "Cisco ISE read-only shell. Type ? for commands, help COMMAND for details."
    prompt = "ise> "

    def __init__(self, *, env_file=None, client=None, cfg=None, dataconnect=None,
                 stdin=None, stdout=None):
        super().__init__(stdin=stdin, stdout=stdout)
        self.use_rawinput = stdin is None
        self.env_file = env_file
        self.client = client
        self.cfg = cfg or getattr(client, "cfg", None)
        self.dataconnect = dataconnect
        self.parser = build_parser(require_command=True)
        self._completion_cache = {}
        if self.use_rawinput:
            self._enable_history()

    def _enable_history(self):
        try:
            import readline
            history = Path(os.environ.get(
                "ISE_CLI_HISTORY", Path.home() / ".local/state/ise-cli/history"))
            history.parent.mkdir(parents=True, exist_ok=True)
            if history.exists():
                readline.read_history_file(history)
            readline.set_history_length(1000)
            readline.parse_and_bind("set show-all-if-ambiguous on")
            readline.parse_and_bind("set completion-ignore-case on")
            atexit.register(readline.write_history_file, history)
        except (ImportError, OSError):
            pass

    def _runtime(self, command):
        if command == "schema":
            return
        dataconnect_only = command in REST_OPTIONAL_COMMANDS
        if self.cfg is None:
            self.cfg = _load_config(self.env_file, require_rest=not dataconnect_only)
        if self.client is None and _rest_ready(self.cfg):
            self.client = ISEOperatorClient(self.cfg)
        if self.client is None and not dataconnect_only:
            raise CLIError("ISE_HOST, ISE_MNT_HOST, ISE_USER, and ISE_PASS are required")
        if self.cfg is None:
            self.cfg = getattr(self.client, "cfg", None)
        if (self.dataconnect is None and self.cfg is not None
                and getattr(self.cfg, "dataconnect_ready", False)):
            self.dataconnect = DataConnectClient(self.cfg)

    def default(self, line):
        try:
            words = shlex.split(line)
        except ValueError as error:
            self.stdout.write(f"parse error: {error}\n")
            return False
        try:
            with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stdout):
                args = self.parser.parse_args(words)
        except SystemExit:
            return False
        try:
            self._runtime(args.command)
            result = _execute(args, self.client, self.cfg, self.dataconnect)
            render(result, args.output, args.select, stream=self.stdout)
        except CLIError as error:
            self.stdout.write(f"error: {error}\n")
        except KeyboardInterrupt:
            self.stdout.write("\ninterrupted\n")
        except Exception as error:
            self.stdout.write(f"error: {error}\n")
        return False

    def do_help(self, argument):
        """Show available commands or detailed help for one command."""
        name = argument.strip()
        if name:
            parser = _subparser(self.parser, name)
            if parser is None:
                self.stdout.write(f"unknown command: {name}\n")
            else:
                self.stdout.write(parser.format_help())
            return
        self.stdout.write(self.parser.format_help())
        self.stdout.write("REPL commands: help, ?, exit, quit\n")

    def do_exit(self, _argument):
        """Exit the ISE shell."""
        return True

    def do_quit(self, argument):
        """Exit the ISE shell."""
        return self.do_exit(argument)

    def do_EOF(self, argument):
        self.stdout.write("\n")
        return self.do_exit(argument)

    def emptyline(self):
        return False

    def completenames(self, text, *_ignored):
        names = sorted((*COMMAND_SCHEMAS, "help", "exit", "quit"))
        return self._matching(names, text, add_space=True)

    def complete_help(self, text, *_ignored):
        return self._matching((*COMMAND_SCHEMAS, "help", "exit", "quit"), text)

    def completedefault(self, text, line, begidx, endidx):
        return self.completion_candidates(line, cursor=endidx)

    def completion_candidates(self, line, *, cursor=None):
        """Return context-aware readline candidates for an interactive command line."""
        prefix = line[:len(line) if cursor is None else cursor]
        words = self._completion_words(prefix)
        if not words:
            return self.completenames("")
        if len(words) == 1 and not prefix.endswith((" ", "\t")):
            return self.completenames(words[0])

        command = words[0]
        current = words[-1]
        if command in ("help", "?"):
            return self._matching(COMMAND_SCHEMAS, current)
        parser = _subparser(self.parser, command)
        if parser is None:
            return []

        before = words[1:-1]
        option_actions = {
            option: action for action in parser._actions for option in action.option_strings
        }

        # --option=value is common in shells and should complete like two tokens.
        if current.startswith("-") and "=" in current:
            option, value_prefix = current.split("=", 1)
            action = option_actions.get(option)
            if action is not None and action.nargs != 0:
                values = self._action_values(command, action, value_prefix, before)
                return [f"{option}={value}" for value in values]

        previous = before[-1] if before else None
        action = option_actions.get(previous)
        if action is not None and action.nargs != 0:
            return self._action_values(command, action, current, before[:-1])

        candidates = []
        if current.startswith("-") or current == "":
            used = set(before)
            for action in parser._actions:
                if not action.option_strings or action.help is argparse.SUPPRESS:
                    continue
                repeatable = isinstance(action, argparse._AppendAction)
                if not repeatable and any(option in used for option in action.option_strings):
                    continue
                candidates.extend(action.option_strings)

        if not current.startswith("-"):
            candidates.extend(self._positional_values(
                command, current, self._consumed_positionals(parser, before)))
        return self._matching(candidates, current, add_space=True)

    @staticmethod
    def _completion_words(prefix):
        try:
            words = shlex.split(prefix)
        except ValueError:
            # Keep completion useful while the user is in an unfinished quote.
            words = prefix.split()
        if prefix.endswith((" ", "\t")):
            words.append("")
        return words

    @staticmethod
    def _matching(values, prefix, *, add_space=False):
        prefix_folded = prefix.casefold()
        matches = []
        for value in values:
            value = str(value)
            comparable = value
            if value[:1] in ("'", '"'):
                try:
                    comparable = shlex.split(value)[0]
                except (ValueError, IndexError):
                    pass
            if comparable.casefold().startswith(prefix_folded) and value not in matches:
                matches.append(value)
        matches.sort(key=str.casefold)
        if add_space and len(matches) == 1:
            matches[0] += " "
        return matches

    def _action_values(self, command, action, prefix, before):
        if action.choices is not None:
            return self._matching(action.choices, prefix, add_space=True)
        destination = action.dest
        if destination == "env_file":
            return self._path_values(prefix)
        if destination == "output":
            return self._matching(("table", "json", "jsonl", "csv"), prefix,
                                  add_space=True)
        if destination == "status":
            return self._matching(COMPLETION_STATUS_VALUES.get(command, ()), prefix,
                                  add_space=True)
        if destination == "filter":
            return self._matching(COMPLETION_FILTER_FIELDS.get(command, ()), prefix)
        if destination == "select":
            return self._select_values(command, prefix)
        if destination == "identifier":
            return self._quote_values(self._endpoint_values(prefix), prefix)
        if destination in ("node", "psn"):
            return self._quote_values(self._node_values(prefix), prefix)
        if destination == "profile":
            return self._quote_values(self._dc_values(
                "ENDPOINTS_DATA", "ENDPOINT_POLICY", prefix), prefix)
        if destination in ("nad", "device"):
            return self._quote_values(self._ers_completion_values(
                "nads", "/config/networkdevice", prefix), prefix)
        if destination == "username":
            if command == "tacacs-activity":
                return self._quote_values(self._ers_completion_values(
                    "tacacs-users", "/config/internaluser", prefix), prefix)
            table = "RADIUS_AUTHENTICATIONS"
            return self._quote_values(self._dc_values(table, "USERNAME", prefix), prefix)
        return []

    @staticmethod
    def _consumed_positionals(parser, words):
        option_actions = {
            option: action for action in parser._actions for option in action.option_strings
        }
        positionals = []
        skip_value = False
        for word in words:
            if skip_value:
                skip_value = False
                continue
            option = word.split("=", 1)[0] if word.startswith("-") else None
            action = option_actions.get(option)
            if action is not None:
                skip_value = action.nargs != 0 and "=" not in word
                continue
            positionals.append(word)
        return positionals

    def _positional_values(self, command, prefix, positionals):
        if command in ("endpoint", "resolve", "session", "auth-status", "secure-client"):
            return [] if positionals else self._quote_values(
                self._endpoint_values(prefix), prefix)
        if command == "endpoints":
            return self._endpoint_search_values(prefix, include_legacy=not positionals)
        if command == "endpoint-fields":
            return [] if positionals else self._endpoint_field_name_values(prefix)
        if command == "schema":
            return [] if positionals else list(COMMAND_SCHEMAS)
        if command == "dataconnect-schema":
            return [] if positionals else self._quote_values(
                self._dataconnect_tables(prefix), prefix)
        if command == "get":
            if not positionals:
                return ["ers", "openapi", "mnt"]
            if len(positionals) == 1:
                return self._get_paths(positionals[0])
        return []

    def _select_values(self, command, prefix):
        selected, separator, field_prefix = prefix.rpartition(",")
        fields = DATACONNECT_REPORTS.get(command, {}).get("columns", ())
        if not fields:
            fields = ("id", "name", "description", "hostname", "ipAddress", "mac")
        matches = self._matching((str(field).lower() for field in fields), field_prefix)
        lead = f"{selected}," if separator else ""
        return [lead + match for match in matches]

    def _endpoint_field_name_values(self, prefix=""):
        def load():
            values = set(ENDPOINT_FIELD_ALIASES)
            try:
                self._completion_runtime("endpoint-fields")
                values.update(row["field"] for row in _endpoint_fields(
                    self.dataconnect, query=self._completion_query))
            except Exception:
                pass
            return sorted(values, key=str.casefold)

        values = self._cached_completion(("endpoint-field-names",), load)
        return self._matching(values, prefix)

    def _endpoint_search_values(self, prefix, *, include_legacy=False):
        if "=" not in prefix:
            fields = [field + "=" for field in self._endpoint_field_name_values(prefix)]
            if include_legacy and prefix:
                fields.extend(self._quote_values(self._endpoint_values(prefix), prefix))
            return fields
        field, value_prefix = prefix.split("=", 1)
        normalized = (".".join(_field_alias(part) for part in field.split(".", 1))
                      if "." in field else _field_alias(field))
        candidates = list(ENDPOINT_FIELD_ALIASES.get(normalized, ()))
        if not candidates and "." in normalized:
            source, column = normalized.split(".", 1)
            if source in ENDPOINT_CONTEXT_SOURCES:
                candidates = [(source, column.replace("-", "_").upper())]
        values = []
        for source, column in candidates:
            table = ENDPOINT_CONTEXT_SOURCES[source]["table"]
            values.extend(self._dc_values(table, column, value_prefix))
        return [shlex.quote(f"{field}={value}") for value in values
                if str(value).casefold().startswith(value_prefix.casefold())]

    @staticmethod
    def _get_paths(family):
        key = "path" if family == "ers" else "paths"
        paths = []
        for schema in COMMAND_SCHEMAS.values():
            api = str(schema.get("api", "")).lower()
            if family not in api and not (family == "openapi" and "openapi" in api):
                continue
            values = schema.get(key, schema.get("path", schema.get("paths", ())))
            if isinstance(values, str):
                values = (values,)
            for value in values:
                if family == "ers" and value.startswith("/ers"):
                    value = value[4:]
                elif family == "openapi" and value.startswith("/api/v1"):
                    value = value[7:]
                elif family == "mnt" and value.startswith("/admin/API/mnt"):
                    value = value[14:]
                if "{" not in value:
                    paths.append(value)
        return paths

    @staticmethod
    def _path_values(prefix):
        path = Path(prefix or ".").expanduser()
        directory = path if prefix.endswith(os.sep) else path.parent
        name_prefix = "" if prefix.endswith(os.sep) else path.name
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
        except OSError:
            return []
        lead = "" if str(directory) == "." else str(directory) + os.sep
        values = []
        for entry in entries:
            if entry.name.casefold().startswith(name_prefix.casefold()):
                values.append(lead + entry.name + (os.sep if entry.is_dir() else ""))
        return values

    @staticmethod
    def _quote_values(values, prefix):
        # readline replaces the current token; shell quoting keeps names containing spaces valid.
        return [shlex.quote(str(value)) for value in values
                if str(value).casefold().startswith(prefix.casefold())]

    def _cached_completion(self, key, loader):
        now = time.monotonic()
        cached = self._completion_cache.get(key)
        if cached and now - cached[0] < COMPLETION_CACHE_TTL:
            return cached[1]
        try:
            values = []
            for value in loader():
                if value not in values:
                    values.append(value)
                if len(values) >= COMPLETION_LIMIT:
                    break
            values = tuple(values)
        except Exception:
            values = ()
        self._completion_cache[key] = (now, values)
        return values

    def _completion_query(self, sql, parameters=None):
        """Return immediately instead of waiting behind production DB pacing."""
        query_if_ready = getattr(self.dataconnect, "query_if_ready", None)
        if query_if_ready is not None:
            return query_if_ready(sql, parameters)
        return self.dataconnect.query(sql, parameters)

    def _completion_runtime(self, command):
        # Completion must never print config/network failures or break the prompt.
        with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stdout):
            self._runtime(command)

    @staticmethod
    def _like_prefix(prefix):
        return prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def _dc_values(self, table, column, prefix, *, min_prefix=COMPLETION_MIN_LIVE_PREFIX):
        normalized_prefix = prefix.strip()
        if len(normalized_prefix) < min_prefix:
            return ()
        production_safe = bool(getattr(self.cfg, "cli_production_safe", True))
        allow_expensive = bool(getattr(self.cfg, "cli_allow_expensive", False))
        if (table.upper() not in _SAFE_LIVE_COMPLETION_TABLES
                and production_safe and not allow_expensive):
            # FETCH FIRST bounds returned rows, not Oracle scan/group work.
            # Never turn a Tab press into a broad query over high-volume event
            # views unless the operator explicitly enabled expensive CLI work.
            return ()
        base_prefix = normalized_prefix[:min_prefix]

        def load(query_prefix):
            self._completion_runtime("dataconnect-schema")
            if self.dataconnect is None:
                return ()
            source = next((spec for spec in ENDPOINT_CONTEXT_SOURCES.values()
                           if spec["table"] == table), None)
            timestamp = source["timestamp"][0] if source and table != "ENDPOINTS_DATA" else ""
            recent = ""
            if timestamp:
                recent = " AND " + recent_event_predicate(
                    timestamp, getattr(self.cfg, "dataconnect_event_window_hours", 6))
            sql = (
                f"SELECT DISTINCT {column} AS value FROM {table} "
                f"WHERE {column} IS NOT NULL{recent} "
                f"AND UPPER({column}) LIKE :prefix ESCAPE '\\' "
                f"FETCH FIRST {COMPLETION_LIMIT} ROWS ONLY")
            rows = self._completion_query(
                sql, {"prefix": self._like_prefix(query_prefix.upper())})
            if rows is None:
                return ()
            return (row.get("value") for row in rows if row.get("value") not in (None, ""))

        key = ("dc", table, column, base_prefix.casefold())
        values = self._cached_completion(key, lambda: load(base_prefix))
        if len(values) >= COMPLETION_LIMIT and normalized_prefix != base_prefix:
            key = ("dc", table, column, normalized_prefix.casefold())
            values = self._cached_completion(key, lambda: load(normalized_prefix))
        return tuple(value for value in values
                     if str(value).casefold().startswith(normalized_prefix.casefold()))

    def _ers_completion_values(self, kind, path, prefix):
        """Complete configuration names without querying high-volume event views."""
        normalized_prefix = prefix.strip()
        if len(normalized_prefix) < COMPLETION_MIN_LIVE_PREFIX:
            return ()
        base_prefix = normalized_prefix[:COMPLETION_MIN_LIVE_PREFIX]

        def load():
            try:
                self._completion_runtime(kind)
                if self.client is None:
                    return ()
                rows = self.client.get_ers(
                    path, {"size": 100, "page": 1},
                    api_name=f"cli_completion_{kind.replace('-', '_')}")
                return (
                    row.get("name") for row in rows or ()
                    if isinstance(row, dict) and row.get("name")
                    and str(row["name"]).casefold().startswith(base_prefix.casefold())
                )
            except Exception:
                return ()

        values = self._cached_completion(("ers", kind, base_prefix.casefold()), load)
        return tuple(value for value in values
                     if str(value).casefold().startswith(normalized_prefix.casefold()))

    def _endpoint_values(self, prefix):
        normalized_prefix = prefix.strip()
        if len(normalized_prefix) < COMPLETION_MIN_LIVE_PREFIX:
            return ()
        base_prefix = normalized_prefix[:COMPLETION_MIN_LIVE_PREFIX]

        def load(query_prefix):
            self._completion_runtime("endpoint-report")
            if self.dataconnect is None:
                return ()
            like = self._like_prefix(query_prefix.upper())
            sql = (
                "SELECT MAC_ADDRESS, ENDPOINT_IP, HOSTNAME FROM ENDPOINTS_DATA "
                "WHERE UPPER(MAC_ADDRESS) LIKE :prefix ESCAPE '\\' "
                "OR UPPER(ENDPOINT_IP) LIKE :prefix ESCAPE '\\' "
                "OR UPPER(HOSTNAME) LIKE :prefix ESCAPE '\\' "
                f"FETCH FIRST {COMPLETION_LIMIT} ROWS ONLY")
            rows = self._completion_query(sql, {"prefix": like})
            if rows is None:
                return ()
            values = []
            for row in rows:
                values.extend(row.get(field) for field in (
                    "hostname", "endpoint_ip", "mac_address"))
            return (value for value in values if value not in (None, ""))

        key = ("endpoints", base_prefix.casefold())
        values = self._cached_completion(key, lambda: load(base_prefix))
        if len(values) >= COMPLETION_LIMIT and normalized_prefix != base_prefix:
            key = ("endpoints", normalized_prefix.casefold())
            values = self._cached_completion(key, lambda: load(normalized_prefix))
        return tuple(value for value in values
                     if str(value).casefold().startswith(normalized_prefix.casefold()))

    def _dataconnect_tables(self, prefix):
        known = set()
        for report in DATACONNECT_REPORTS.values():
            known.update(value for key, value in report.items()
                         if key in ("table", "condition_table"))
            known.update(report.get("tables", {}).values())
        live = self._dc_values("USER_TAB_COLUMNS", "TABLE_NAME", prefix, min_prefix=1)
        return sorted(known | set(live), key=str.casefold)

    def _node_values(self, prefix):
        key = ("nodes", prefix.casefold())

        def load():
            values = list(self._dc_values("KEY_PERFORMANCE_METRICS", "ISE_NODE", prefix))
            try:
                self._completion_runtime("nodes")
                rows = self.client.get_pan_api(
                    "/deployment/node", api_name="cli_completion_nodes")
                if isinstance(rows, dict):
                    rows = rows.get("response", rows.get("items", ()))
                for row in rows or ():
                    if isinstance(row, dict):
                        values.append(first_nonempty(row, "hostname", "name", "fqdn"))
            except Exception:
                pass
            return (value for value in values if value)

        return self._cached_completion(key, load)

    def close(self):
        if self.dataconnect is not None:
            self.dataconnect.close()


def main(argv=None, *, client=None, cfg=None, dataconnect=None, stdin=None, stdout=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        shell = ISEShell(env_file=args.env_file, client=client, cfg=cfg,
                         dataconnect=dataconnect, stdin=stdin, stdout=stdout)
        try:
            shell.cmdloop()
            return 0
        finally:
            shell.close()
    try:
        if client is None and args.command != "schema":
            dataconnect_only = args.command in REST_OPTIONAL_COMMANDS
            if cfg is None:
                cfg = _load_config(args.env_file, require_rest=not dataconnect_only)
            if _rest_ready(cfg):
                client = ISEOperatorClient(cfg)
        elif cfg is None:
            cfg = getattr(client, "cfg", None)
        if (dataconnect is None and cfg is not None
                and getattr(cfg, "dataconnect_ready", False)):
            dataconnect = DataConnectClient(cfg)
        result = _execute(args, client, cfg, dataconnect)
        render(result, args.output, args.select, stream=stdout)
        return 0
    except CLIError as error:
        print(f"ise-cli: error: {error}", file=sys.stderr)
        return 2
    finally:
        if dataconnect is not None:
            dataconnect.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())
