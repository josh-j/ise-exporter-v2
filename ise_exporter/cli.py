"""Read-only Cisco ISE operator CLI built on the exporter's API client.

The command surface intentionally exposes GET operations only. Inventory commands
are bounded by default so an exploratory query cannot accidentally enumerate an
80k-endpoint deployment; callers must opt into ``--all`` explicitly.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.pretty import Pretty
from rich.table import Table
from rich.text import Text

from .clients.rest import ISERestClient
from .config import Config
from .util import (first_nonempty, normalize_agent_version, normalize_posture,
                   parse_other_attr_string, parse_posture_report)


COMMAND_SCHEMAS = {
    "health": {
        "api": "ERS + MnT", "host_env": ["ISE_HOST", "ISE_MNT_HOST"],
        "method": "GET", "paths": ["/ers", "/admin"],
    },
    "endpoints": {
        "api": "ERS", "host_env": "ISE_HOST", "method": "GET",
        "path": "/ers/config/endpoint", "bounded_default": 100,
    },
    "endpoint": {
        "api": "ERS + optional MnT", "host_env": ["ISE_HOST", "ISE_MNT_HOST"],
        "method": "GET", "paths": [
            "/ers/config/endpoint?filter=mac.EQ.{identifier}",
            "/ers/config/endpoint/{id}",
            "/admin/API/mnt/Session/MACAddress/{mac}",
        ],
    },
    "sessions": {
        "api": "MnT XML", "host_env": "ISE_MNT_HOST", "method": "GET",
        "path": "/admin/API/mnt/Session/ActiveList",
    },
    "auth-status": {
        "api": "MnT XML", "host_env": "ISE_MNT_HOST", "method": "GET",
        "path": "/admin/API/mnt/AuthStatus/MACAddress/{mac}/{seconds}/{limit}/All",
    },
    "secure-client": {
        "api": "MnT XML", "host_env": "ISE_MNT_HOST", "method": "GET",
        "path": "/admin/API/mnt/Session/MACAddress/{mac}",
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
    "get": {
        "api": "ERS, OpenAPI, or MnT", "method": "GET only",
        "host_env": {"ers": "ISE_HOST", "openapi": "ISE_HOST", "mnt": "ISE_MNT_HOST"},
    },
}


class CLIError(RuntimeError):
    pass


def _add_output_args(parser):
    parser.add_argument("-o", "--output", choices=("table", "json", "jsonl", "csv"),
                        default="table", help="output format (default: table)")
    parser.add_argument("--select", metavar="FIELDS",
                        help="comma-separated fields to retain")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ise-cli",
        description="Read-only Cisco ISE operator CLI (ERS, OpenAPI, MnT)",
    )
    parser.add_argument("--env-file", help="dotenv file to load after ./.env")
    parser.add_argument("--version", action="version", version="%(prog)s 2.0.0")
    subs = parser.add_subparsers(dest="command", required=True)

    def command(name, help_text):
        sub = subs.add_parser(name, help=help_text)
        _add_output_args(sub)
        return sub

    command("health", "check PAN/ERS and MnT reachability")
    command("nodes", "list deployment nodes")

    for name, help_text in (
        ("endpoints", "list endpoints from ERS"),
        ("nads", "list network access devices from ERS"),
        ("profiles", "list profiler profiles from ERS"),
        ("tacacs-users", "list internal users used by Device Administration"),
    ):
        sub = command(name, help_text)
        sub.add_argument("--limit", type=int, default=100,
                         help="maximum rows (default: 100)")
        sub.add_argument("--all", action="store_true",
                         help="explicitly enumerate every result")
        sub.add_argument("--filter", action="append", default=[],
                         help="ISE ERS filter expression; repeatable")

    sub = command("sessions", "list active MnT sessions")
    sub.add_argument("--limit", type=int, default=100)
    sub.add_argument("--all", action="store_true")

    sub = command("endpoint", "inspect one endpoint by MAC or ERS id")
    sub.add_argument("identifier")
    sub.add_argument("--id", action="store_true", help="identifier is an ERS endpoint id")
    sub.add_argument("--include-session", action="store_true",
                     help="also query MnT Session/MACAddress")

    sub = command("auth-status", "show recent MnT authentication status for a MAC")
    sub.add_argument("mac")
    sub.add_argument("--seconds", type=int, default=600)
    sub.add_argument("--limit", type=int, default=20)

    sub = command("secure-client", "inspect Secure Client posture attributes for a MAC")
    sub.add_argument("mac")
    sub.add_argument("--include-all", action="store_true",
                     help="include every parsed other_attr_string field")

    sub = command("schema", "show command API routes and response contract")
    sub.add_argument("name", nargs="?", choices=tuple(COMMAND_SCHEMAS))

    sub = command("get", "perform an explicit read-only GET against an API family")
    sub.add_argument("family", choices=("ers", "openapi", "mnt"))
    sub.add_argument("path", help="family-relative path beginning with /")
    sub.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    sub.add_argument("--all", action="store_true", help="follow ERS pagination")
    sub.add_argument("--no-unwrap", action="store_true",
                     help="keep the OpenAPI response envelope")
    return parser


def _load_config(env_file=None):
    load_dotenv(interpolate=False)
    deployed = env_file or os.environ.get(
        "ISE_EXPORTER_ENV_FILE", "/etc/ise-exporter/ise-exporter.env")
    if deployed and os.path.isfile(deployed):
        load_dotenv(deployed, interpolate=False)
    cfg = Config.from_env()
    if not cfg.ise_host or not cfg.ise_mnt_host or not cfg.ise_user or not cfg.ise_pass:
        raise CLIError("ISE_HOST, ISE_MNT_HOST, ISE_USER, and ISE_PASS are required")
    return cfg


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


def _endpoint_detail(client, identifier, by_id=False):
    endpoint_id = identifier
    if not by_id:
        matches = client.get_ers(
            "/config/endpoint", {"size": 2, "filter": f"mac.EQ.{identifier}"},
            api_name="cli_endpoint_lookup",
        )
        if not matches:
            raise CLIError(f"endpoint not found for MAC {identifier}")
        endpoint_id = matches[0].get("id")
    raw = client.get_ers(f"/config/endpoint/{endpoint_id}", api_name="cli_endpoint_detail")
    if raw is None:
        raise CLIError(f"endpoint detail unavailable for {endpoint_id}")
    return raw.get("ERSEndPoint", raw) if isinstance(raw, dict) else raw


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


def _execute(args, client, cfg):
    command = args.command
    if command == "health":
        health = client.health_check()
        return [
            {"service": "PAN/ERS", "host": cfg.ise_host, "reachable": health["pan"]},
            {"service": "MnT", "host": cfg.ise_mnt_host, "reachable": health["mnt"]},
        ]
    if command == "nodes":
        result = client.get_pan_api("/deployment/node", api_name="cli_nodes")
        if result is None:
            raise CLIError("ISE returned no deployment-node response")
        return result
    inventory_paths = {
        "endpoints": "/config/endpoint",
        "nads": "/config/networkdevice",
        "profiles": "/config/profilerprofile",
        "tacacs-users": "/config/internaluser",
    }
    if command in inventory_paths:
        return _ers_rows(client, inventory_paths[command], limit=args.limit,
                         all_rows=args.all, filters=args.filter)
    if command == "sessions":
        rows = _mnt_sessions(client, "/Session/ActiveList", "cli_sessions")
        return rows if args.all else rows[:args.limit]
    if command == "endpoint":
        detail = _endpoint_detail(client, args.identifier, args.id)
        if args.include_session:
            mac = detail.get("mac") or detail.get("name") or args.identifier
            detail = dict(detail)
            detail["mnt_sessions"] = _mnt_sessions(
                client, f"/Session/MACAddress/{mac}", "cli_endpoint_session")
        return detail
    if command == "auth-status":
        if args.seconds < 1 or args.limit < 1:
            raise CLIError("--seconds and --limit must be at least 1")
        return _mnt_sessions(
            client, f"/AuthStatus/MACAddress/{args.mac}/{args.seconds}/{args.limit}/All",
            "cli_auth_status",
        )
    if command == "secure-client":
        return _secure_client(client, args.mac, args.include_all)
    if command == "schema":
        return COMMAND_SCHEMAS if args.name is None else COMMAND_SCHEMAS[args.name]
    if command == "get":
        if not args.path.startswith("/") or "://" in args.path or ".." in args.path:
            raise CLIError("path must be family-relative, start with '/', and contain no '..'")
        params = _params(args.param)
        if args.family == "ers":
            result = client.get_ers(args.path, params or None, get_all=args.all,
                                    api_name="cli_get_ers")
        elif args.family == "openapi":
            if params:
                raise CLIError("OpenAPI --param is not supported by the current transport")
            result = client.get_pan_api(args.path, api_name="cli_get_openapi",
                                        unwrap=not args.no_unwrap)
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
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
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
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        return
    rows = _records(value)
    if output == "jsonl":
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        return
    fields = _fields(rows)
    if output == "csv":
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows({key: _cell(value) for key, value in row.items()} for row in rows)
        return
    if not rows:
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


def main(argv=None, *, client=None, cfg=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if client is None and args.command != "schema":
            cfg = _load_config(args.env_file)
            client = ISERestClient(cfg)
        elif cfg is None:
            cfg = getattr(client, "cfg", None)
        result = _execute(args, client, cfg)
        render(result, args.output, args.select)
        return 0
    except CLIError as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    sys.exit(main())
