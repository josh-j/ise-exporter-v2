#!/usr/bin/env bash
# Probe the PAN/ERS endpoint object. Posture fields usually are not here on ISE 3.3;
# use curl_mnt_endpoint_attributes.sh for the live MnT other-attributes source.
set -euo pipefail

if [[ ${1:-} == --schema || ${1:-} == --schema-only ]]; then
  printf '%s\n' '{
  "api": "ERS",
  "method": "GET",
  "host_env": "ISE_HOST",
  "lookup_path": "/ers/config/endpoint?filter=mac.EQ.{MAC}",
  "detail_path": "/ers/config/endpoint/{endpoint_id}",
  "response": {
    "envelope": "ERSEndPoint",
    "fields": ["id", "name", "mac", "profileId", "groupId", "customAttributes", "mfcAttributes"]
  }
}'
  exit 0
fi

mac=${1:?usage: tools/curl_ers_endpoint_detail.sh MAC}
: "${ISE_HOST:?set ISE_HOST to the PAN/ERS node}"
: "${ISE_USER:?set ISE_USER}"
: "${ISE_PASS:?set ISE_PASS}"
ers_port=${ERS_PORT:-9060}
base="https://${ISE_HOST}:${ers_port}/ers/config/endpoint"

search=$(curl --fail-with-body --silent --show-error --insecure \
  --user "${ISE_USER}:${ISE_PASS}" \
  --header 'Accept: application/json' \
  --get --data-urlencode "filter=mac.EQ.${mac}" "${base}")
endpoint_id=$(jq -r '.SearchResult.resources[0].id // empty' <<<"${search}")
if [[ -z ${endpoint_id} ]]; then
  echo "no ERS endpoint found for ${mac} on ${ISE_HOST}" >&2
  exit 1
fi

echo "ERS host=${ISE_HOST} endpoint_id=${endpoint_id}" >&2
curl --fail-with-body --silent --show-error --insecure \
  --user "${ISE_USER}:${ISE_PASS}" \
  --header 'Accept: application/json' \
  "${base}/${endpoint_id}" \
  | jq '.ERSEndPoint | {
      id, name, mac, profileId, groupId,
      customAttributes, mfcAttributes
    }'
