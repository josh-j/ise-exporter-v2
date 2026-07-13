#!/usr/bin/env bash
# Curl the exact MnT Session/MACAddress path used by authz._fetch_detail(), then
# parse other_attr_string with the exporter's own parser and posture helpers.
set -euo pipefail

if [[ ${1:-} == --schema || ${1:-} == --schema-only ]]; then
  printf '%s\n' '{
  "api": "MnT XML",
  "method": "GET",
  "host_env": "ISE_MNT_HOST",
  "path": "/admin/API/mnt/Session/MACAddress/{MAC}",
  "top_level_fields": ["posture_status"],
  "other_attr_string_fields": [
    "PostureAgentVersion",
    "PostureApplicable",
    "PostureAssessmentStatus",
    "PostureReport",
    "PostureStatus"
  ],
  "derived_fields": {
    "PosturePolicyResult": ["policy", "result"]
  }
}'
  exit 0
fi

mac=${1:?usage: tools/curl_secure_client_attributes.sh MAC}
: "${ISE_MNT_HOST:?set ISE_MNT_HOST to the MnT node}"
: "${ISE_USER:?set ISE_USER}"
: "${ISE_PASS:?set ISE_PASS}"

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
url="https://${ISE_MNT_HOST}/admin/API/mnt/Session/MACAddress/${mac}"

echo "MnT host=${ISE_MNT_HOST} path=/Session/MACAddress/${mac}" >&2
curl --fail-with-body --silent --show-error --insecure \
  --user "${ISE_USER}:${ISE_PASS}" \
  --header 'Accept: application/xml' "${url}" \
  | PYTHONPATH="${repo_root}${PYTHONPATH:+:${PYTHONPATH}}" python -c '
import sys
import xml.etree.ElementTree as ET

from ise_exporter.util import parse_other_attr_string, parse_posture_report

root = ET.parse(sys.stdin).getroot()
fields = {}
for element in root.iter():
    name = element.tag.rsplit("}", 1)[-1]
    value = (element.text or "").strip()
    if value:
        fields[name] = value

other = parse_other_attr_string(fields.get("other_attr_string", ""))
ordered = (
    "PostureAgentVersion",
    "PostureApplicable",
    "PostureAssessmentStatus",
    "PostureReport",
    "PostureStatus",
)
found = False
status = fields.get("posture_status")
if status:
    print(f"posture_status\t{status}")
    found = True
for name in ordered:
    value = other.get(name)
    if value:
        print(f"{name}\t{value}")
        found = True
for policy, result in parse_posture_report(other.get("PostureReport", "")):
    print(f"PosturePolicyResult\t{policy}\t{result}")
if not found:
    raise SystemExit("MnT session contained no Secure Client posture attributes")
'
