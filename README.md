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
- `deploy/` — Dockerfile, docker-compose, systemd unit

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

    sudo useradd --system --no-create-home ise-exporter
    sudo install -d -o root -g ise-exporter -m 750 /opt/ise-exporter /etc/ise-exporter
    sudo python3 -m venv /opt/ise-exporter/.venv
    sudo /opt/ise-exporter/.venv/bin/pip install /path/to/ise-exporter
    sudo cp .env /etc/ise-exporter/ise-exporter.env      # root:ise-exporter, 0640
    sudo cp deploy/ise-exporter.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now ise-exporter

The unit is hardened (`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`,
`ReadOnlyPaths=/etc/ise-exporter`) — appropriate since that env file holds the
pxGrid client key.

## Plane ownership
| plane | source | notes |
|-------|--------|-------|
| sessions / authz(passed) / models | stream (or poll fallback) | |
| failed auth / policy-set / matched-rule | MnT poll | not on session topic; runs in both modes |
| NAD inventory | ERS poll | label join for streamed sessions |
| nodes / certs / license / backup / patch | PAN OpenAPI poll | no pxGrid equivalent |
