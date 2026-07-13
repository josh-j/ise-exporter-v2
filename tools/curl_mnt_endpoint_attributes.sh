#!/usr/bin/env bash
# Probe the MnT session detail used by the exporter for PostureReport,
# PostureAgentVersion, PostureStatus, and the rest of other_attr_string.
set -euo pipefail

mac=${1:?usage: tools/curl_mnt_endpoint_attributes.sh MAC}
: "${ISE_MNT_HOST:?set ISE_MNT_HOST to the MnT node}"
: "${ISE_USER:?set ISE_USER}"
: "${ISE_PASS:?set ISE_PASS}"
url="https://${ISE_MNT_HOST}/admin/API/mnt/Session/MACAddress/${mac}"

echo "MnT host=${ISE_MNT_HOST} path=/Session/MACAddress/${mac}" >&2
curl --fail-with-body --silent --show-error --insecure \
  --user "${ISE_USER}:${ISE_PASS}" \
  --header 'Accept: application/xml' "${url}" \
  | python -c '
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.stdin).getroot()
wanted = {"other_attr_string", "posture_status", "calling_station_id", "acs_server"}
found = False
for element in root.iter():
    name = element.tag.rsplit("}", 1)[-1]
    value = (element.text or "").strip()
    if name in wanted and value:
        print(f"{name}={value}")
        found = True
if not found:
    raise SystemExit("MnT response contained none of the expected endpoint/session attributes")
'
