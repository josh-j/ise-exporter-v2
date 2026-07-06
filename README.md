# ise-exporter

Prometheus exporter for Cisco ISE. Two execution engines sharing one metric
registry: a REST **poll** scheduler (health plane, NAD inventory, sessions) and
an optional pxGrid **stream** engine (sessions/endpoints/models via topics).

Requires Python ≥ 3.10. Exposes Prometheus metrics on `:9618/metrics` by default.

## Layout
- `ise_exporter/config.py` — all env config (one dataclass)
- `ise_exporter/metrics.py` — central metric registry (import surface)
- `ise_exporter/clients/` — transport only (ERS/PAN/MnT REST, pxGrid control)
- `ise_exporter/collectors/` — poll-mode metric producers
- `ise_exporter/scheduler.py` — poll engine (interval tiers, failure gating)
- `ise_exporter/streaming.py` — pxGrid stream engine (subscribe→snapshot→drain→live)
- `dashboards/` — Grafana JSON
- `deploy/` — Dockerfile, docker-compose, systemd unit, `install.sh` (idempotent install/upgrade)

## Configure
All configuration is environment variables. Start from the template:

    cp .env.example .env        # then edit

Required: `ISE_HOST` (PAN/ERS node), `ISE_MNT_HOST` (MnT node), `ISE_USER`,
`ISE_PASS`. Everything else has a default — see `.env.example` for the full set
and `ise_exporter/config.py` for the authoritative list. Common knobs:

| var | default | purpose |
|-----|---------|---------|
| `EXPORTER_PORT` | `9618` | metrics listen port |
| `SCRAPE_INTERVAL` | `120` | base poll loop period (s) |
| `FAST_INTERVAL` / `MEDIUM_INTERVAL` / `SLOW_INTERVAL` | `60` / `300` / `3600` | per-tier collector cadence (s) |
| `MAX_WORKERS` | `10` | concurrency for the per-MAC authz fan-out |
| `COLLECT_AUTHZ` | `true` | per-MAC authz/policy-set/matched-rule metrics |
| `COLLECT_PXGRID_ENDPOINTS` | `true` | bulk pxGrid `getEndpoints` model breakdown |
| `COLLECT_PXGRID_STREAM` | `false` | replace sessions+endpoints polling with pxGrid topics |
| `PXGRID_HOST` / `PXGRID_NODE_NAME` | — | pxGrid controller + registered consumer name |
| `PXGRID_CLIENT_CERT` / `PXGRID_CLIENT_KEY` / `PXGRID_CA_BUNDLE` | — | pxGrid mTLS material (key must be an unencrypted PEM) |
| `PXGRID_PROFILER_HIERARCHY_TTL` | `3600` | how often to re-fetch the profiler category/parent catalog (seconds) |

pxGrid (model collector or streaming) needs `PXGRID_HOST`, `PXGRID_NODE_NAME`,
`PXGRID_CLIENT_CERT`, and `PXGRID_CLIENT_KEY`. `PXGRID_CA_BUNDLE` is strongly
recommended so the exporter validates the ISE server certificate.
On first use, the exporter calls pxGrid `AccountActivate`; if ISE returns
`PENDING` or `DISABLED`, approve/enable the `PXGRID_NODE_NAME` account in ISE and
restart or wait for the next retry. Endpoint model collection uses pxGrid
`getEndpoints` with a timestamp filter and paging, so it can download more than
one page of endpoints.
If `COLLECT_PXGRID_STREAM=true` but the pxGrid creds are incomplete, the exporter
falls back to polling sessions/endpoints rather than dropping them.

Endpoint model collection also joins ISE's profiler *policy catalog* (category/
parent hierarchy from Policy > Profiling, via the `com.cisco.ise.config.profiler`
pxGrid service's `getProfiles`) onto the per-profile endpoint counts, emitting
`ise_endpoints_by_profile_all{category,parent,profile}` — see
`dashboards/ise-endpoint-profiles.json`. The catalog is cached and re-fetched at
most every `PXGRID_PROFILER_HIERARCHY_TTL` seconds (default `3600`) since it
rarely changes; a failed fetch (e.g. a pxGrid Group not scoped to that service)
just falls back to `category="unknown"` rather than breaking the per-profile
counts themselves.

## pxGrid setup (ISE side)

Only needed if you want `COLLECT_PXGRID_ENDPOINTS` (default on) or
`COLLECT_PXGRID_STREAM`. Skip this if you're running poll-only against ERS/MnT.
The flow below is for on-prem pxGrid 2.0 and is compatible with Cisco ISE 3.3
and 3.4; the exporter does not require pxGrid Cloud or the 3.4-only filtering
feature.

**1. Enable the pxGrid persona.** *Administration > System > Deployment*, edit a
node, check **pxGrid**, save. Cisco recommends a primary + secondary pxGrid
node pair for HA in production, same as PAN HA. The session/endpoint topics
also require the serving PSNs to have **Session Services** enabled (standard
for any PSN already doing 802.1X/MAB).

**2. pxGrid Settings.** *Administration/Work Centers > pxGrid Services > Settings*:
- **Automatically approve new certificate-based accounts** — leave off unless
  you want new clients auto-enabled with no admin approval step. This repo's
  earlier troubleshooting assumed manual approval (`AccountActivate` returns
  `PENDING` until an admin approves it — see step 4).
- **Allow password based account creation** — leave off; this exporter is
  certificate-authenticated only.

**3. Generate the client certificate.** *Administration/Work Centers > pxGrid
Services > Client Management > Certificates* (exact menu path varies slightly
by ISE 3.x patch):
- "I want to": **Generate a single certificate (without a certificate signing
  request)**
- **Common Name (CN)**: match `PXGRID_NODE_NAME` exactly (e.g. `ise-exporter`)
  — this is also the pxGrid node identity, not just the cert subject.
- **Certificate Download Format**: PEM, key in PKCS8 PEM (include cert chain).
- Set a certificate password, click **Create** — ISE emails/downloads a zip
  with the client cert, the (password-protected) private key, and the CA
  chain that signed both.
- **Strip the key passphrase** — the exporter requires an unencrypted PEM key
  (`requests`/`ssl` don't prompt for one):

      openssl rsa -in client-protected.key -out client.key

  If your org's PKI policy requires an external CA instead of ISE's internal
  one: generate a CSR, get it signed externally, then import the resulting
  cert *and* its CA chain into *Administration > System > Certificates >
  Trusted Certificates* so ISE trusts it for mTLS.
- Rename/place the three files to match your env vars, e.g.
  `PXGRID_CLIENT_CERT=/etc/ise-exporter/certs/client.cer`,
  `PXGRID_CLIENT_KEY=/etc/ise-exporter/certs/client.key`,
  `PXGRID_CA_BUNDLE=/etc/ise-exporter/certs/ise-ca.cer` — see the systemd
  section below for permissions.

**4. Approve the client.** The exporter self-registers on first
`AccountActivate` call. In *Administration/Work Centers > pxGrid Services >
Client Management > Clients*, find the row matching `PXGRID_NODE_NAME`
(status **Pending**), select it, click **Approve**. If your ISE version
exposes pxGrid Group-based authorization, consider scoping this client to
read-only session/endpoint/pubsub/profiler-config services rather than the
default unrestricted access — the exporter's code only ever reads, but an
approved pxGrid credential is capable of whatever services your deployment
publishes (ANC, TrustSec, etc.) unless explicitly scoped down. The profiler
category/parent hierarchy (`ise_endpoints_by_profile_all`, see "Endpoint
model collection" above) needs `com.cisco.ise.config.profiler` specifically —
if that service is excluded from the group, its data just falls back to
`category="unknown"` rather than failing the whole client.

If you *do* scope the client to a custom group (say `exporter`), the
least-privilege pxGrid **policy** it needs — REST `gets` on the query services
plus pubsub `subscribe` on the topics streaming mode consumes — is:

| Service | Operation | For |
|---------|-----------|-----|
| `com.cisco.ise.session` | `gets` | session snapshot (getSessions) + poll |
| `com.cisco.ise.endpoint` | `gets` | endpoint snapshot (getEndpoints) |
| `com.cisco.ise.config.profiler` | `gets` | profiler policy catalog (getProfiles) |
| `com.cisco.ise.pubsub` | `subscribe /topic/com.cisco.ise.session` | live session events |
| `com.cisco.ise.pubsub` | `subscribe /topic/com.cisco.ise.endpoint` | live endpoint events |

A subscribe that the group isn't authorized for makes ISE **drop the WebSocket**
right after CONNECT — which reads as a flapping/failing stream, not a clear
"permission denied". The exporter logs `pxGrid SUBSCRIBE <name> topic -> <dest>`
for each subscription so you can see exactly which destination ISE rejected.

The exporter subscribes to the **base** `sessionTopic`
(`/topic/com.cisco.ise.session`) by default — it's on every ISE and authorized
for any session-service client. `sessionTopicAll` (`…​.session.all`) only exists
on ISE 3.3 patch 2 / 3.4+ and needs the group authorized for that specific
topic; set `PXGRID_SESSION_TOPIC_ALL=true` (and add the matching subscribe
policy) only if you actually want it.

**5. Network reachability.** pxGrid 2.0 uses TCP/8910 for both the REST
control plane and the WSS pubsub subscription (streaming mode). In a
multi-PSN deployment, `ServiceLookup` can hand back a *different* node than
`PXGRID_HOST` for the pubsub service — make sure firewall rules cover every
node that could serve `com.cisco.ise.pubsub`, not just the one in your config.

**6. Verify from the exporter side** before enabling streaming in production:

    ise-exporter --pxgrid-check-stream

## Run

### From source

    pip install -e .
    cp .env.example .env         # edit
    ise-exporter --pxgrid-check   # optional: validate pxGrid account/services/probes
    ise-exporter --pxgrid-check-stream  # optional: also validate WSS/STOMP streaming
    ise-exporter
    # metrics at http://localhost:9618/metrics

    pip install -e ".[dev]" && pytest      # tests

### Docker

    # build (run from the repo root so the context includes ise_exporter/)
    docker build -f deploy/Dockerfile -t ise-exporter:2.0.0 .

    # run
    docker run --rm -p 9618:9618 --env-file .env \
      -v "$PWD/deploy/certs:/certs:ro" \
      ise-exporter:2.0.0

Lean multi-stage build (no build tools in the runtime image), runs as
`nobody:nogroup`, and ships a `HEALTHCHECK` that polls `/metrics`.

### docker compose

    cd deploy
    # .env lives at the repo root; certs (if streaming) go in deploy/certs/
    docker compose up -d --build
    docker compose logs -f

The compose service is `read_only` with a tmpfs `/tmp` and `no-new-privileges`,
since the exporter writes nothing to disk. Change `EXPORTER_PORT` in `.env`?
Update the `ports:` mapping in `docker-compose.yml` to match.

### systemd

**Automated (recommended):** `deploy/install.sh` does everything below —
user, directories, venv, package (upgrade-in-place if already installed),
config skeleton (seeded once, never overwritten), permissions, and the
systemd unit. Safe to re-run for upgrades: pull the latest checkout and
run it again.

    git pull   # or clone fresh
    sudo ./deploy/install.sh
    # fresh install: edit /etc/ise-exporter/ise-exporter.env, drop pxGrid
    # certs in /etc/ise-exporter/certs/, then: sudo systemctl restart ise-exporter
    # upgrade: that's it — it restarts the service with the new version

Or run it against a checkout elsewhere: `sudo ./deploy/install.sh /path/to/checkout`.

**Manual**, for reference or if you need to customize a step:

    sudo useradd --system --no-create-home ise-exporter
    sudo install -d -o root -g ise-exporter -m 750 /opt/ise-exporter /etc/ise-exporter
    sudo python3 -m venv /opt/ise-exporter/.venv
    sudo /opt/ise-exporter/.venv/bin/pip install /path/to/ise-exporter
    sudo cp .env /etc/ise-exporter/ise-exporter.env
    sudo chown root:ise-exporter /etc/ise-exporter/ise-exporter.env
    sudo chmod 640 /etc/ise-exporter/ise-exporter.env
    sudo cp deploy/ise-exporter.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now ise-exporter

The unit is hardened (`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`,
`ReadOnlyPaths=/etc/ise-exporter`) — appropriate since that env file holds
`ISE_PASS` in plaintext. `root:ise-exporter, 0640` rather than root-only:
systemd's `EnvironmentFile=` is read by the manager (root) before it drops to
`User=ise-exporter`, so root-only would work for the service itself, but
group-read also lets you run diagnostics as the service account (e.g.
`sudo -u ise-exporter ise-exporter --pxgrid-check`, which reads the file
in-process via `load_dotenv()` rather than inheriting it from systemd).

**pxGrid TLS material** (`PXGRID_CLIENT_CERT`/`_KEY`/`_CA_BUNDLE`) isn't part of
the env file — it's separate files the env file only points to by path. Put
them under the same tree and lock down the private key specifically:

    sudo install -d -o root -g ise-exporter -m 750 /etc/ise-exporter/certs
    sudo cp client.cer client.key ise-ca.cer /etc/ise-exporter/certs/
    sudo chown root:ise-exporter /etc/ise-exporter/certs/*
    sudo chmod 640 /etc/ise-exporter/certs/client.key   # private key — keep this tight
    sudo chmod 644 /etc/ise-exporter/certs/client.cer /etc/ise-exporter/certs/ise-ca.cer  # public certs, fine to read broadly

Then set `PXGRID_CLIENT_CERT=/etc/ise-exporter/certs/client.cer`,
`PXGRID_CLIENT_KEY=/etc/ise-exporter/certs/client.key`, and
`PXGRID_CA_BUNDLE=/etc/ise-exporter/certs/ise-ca.cer` in the env file (paths
are already covered read-only by `ReadOnlyPaths=/etc/ise-exporter`, since it
applies recursively). A missing or unreadable path here fails at first pxGrid
call with a wrapped/cryptic error (`Connection aborted` / `invalid path`) —
check `journalctl -u ise-exporter` right after start for an explicit
`pxGrid client cert/key/CA bundle not found|not readable` line instead; that
check now runs at startup rather than surfacing only when a collector cycle
first needs it.

## Plane ownership
| plane | source | notes |
|-------|--------|-------|
| sessions / authz(passed) / models | stream (or poll fallback) | |
| failed auth / policy-set / matched-rule | MnT poll | not on session topic; runs in both modes |
| NAD inventory | ERS poll | label join for streamed sessions |
| nodes / certs / license / backup / patch | PAN OpenAPI poll | no pxGrid equivalent |
