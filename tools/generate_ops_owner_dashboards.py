#!/usr/bin/env python3
"""Generate one provisionable site-troubleshooting dashboard per NDG ops owner."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata

from prometheus_client.parser import text_string_to_metric_families


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE = ROOT / "dashboards/templates/ise-ops-owner-site.json.tmpl"
DEFAULT_OUTPUT_DIR = ROOT / "dashboards"
MANIFEST = ".generated-ops-owner-dashboards.manifest"
OWNER_METRIC = "ise_network_devices_by_ops_owner"


def _promql_string(value):
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _slug(value):
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-") or "owner"
    digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    if len(slug) > 28:
        slug = f"{slug[:19].rstrip('-')}-{digest}"
    return slug


def _owners_from_metrics(text):
    owners = set()
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            if sample.name != OWNER_METRIC or sample.value <= 0:
                continue
            owner = sample.labels.get("ops_owner", "").strip()
            if owner and owner.lower() not in {"unknown", "other"}:
                owners.add(owner)
    return owners


def _replace(value, replacements):
    if isinstance(value, str):
        for token, replacement in replacements.items():
            value = value.replace(token, replacement)
        return value
    if isinstance(value, list):
        return [_replace(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _replace(item, replacements) for key, item in value.items()}
    return value


def _load_metrics(path):
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text()


def generate(template_path, output_dir, owners):
    template = json.loads(template_path.read_text())
    output_dir.mkdir(parents=True, exist_ok=True)
    slugs = {_slug(owner): owner for owner in owners}
    if len(slugs) != len(owners):
        raise ValueError("ops owner names produced duplicate dashboard slugs")

    written = []
    for slug, owner in sorted(slugs.items()):
        dashboard = _replace(template, {
            "__OPS_OWNER_PROMQL__": _promql_string(owner),
            "__OPS_OWNER_SLUG__": slug,
            "__OPS_OWNER__": owner,
        })
        path = output_dir / f"ise-ops-owner-{slug}.json"
        path.write_text(json.dumps(dashboard, indent=2, ensure_ascii=False) + "\n")
        written.append(path.name)

    manifest_path = output_dir / MANIFEST
    previous = []
    if manifest_path.exists():
        previous = json.loads(manifest_path.read_text()).get("files", [])
    for filename in set(previous) - set(written):
        if re.fullmatch(r"ise-ops-owner-[a-z0-9-]+\.json", filename):
            (output_dir / filename).unlink(missing_ok=True)
    manifest_path.write_text(json.dumps({"files": written}, indent=2) + "\n")
    return [output_dir / filename for filename in written]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("owners", nargs="*", help="Exact Ops Owner NDG leaf names")
    parser.add_argument(
        "--metrics-file",
        help="Prometheus exposition file containing ise_network_devices_by_ops_owner; use - for stdin",
    )
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)

    owners = {owner.strip() for owner in args.owners if owner.strip()}
    if args.metrics_file:
        owners.update(_owners_from_metrics(_load_metrics(args.metrics_file)))
    if not owners:
        parser.error("provide at least one owner or --metrics-file with owner metrics")

    for path in generate(args.template, args.output_dir, owners):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
