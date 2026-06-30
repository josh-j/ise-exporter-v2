# Build the wheel in a throwaway stage so the runtime image carries no build tools.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY ise_exporter ./ise_exporter
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="ise-exporter" \
      org.opencontainers.image.description="Prometheus exporter for Cisco ISE (REST poll + pxGrid stream)" \
      org.opencontainers.image.version="2.0.0"
WORKDIR /app
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

EXPOSE 9618
# run as nobody:nogroup — the exporter needs no filesystem writes
USER 65534:65534

# honors EXPORTER_PORT; hits the metrics endpoint to confirm the server is up
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request; \
urllib.request.urlopen('http://127.0.0.1:'+os.getenv('EXPORTER_PORT','9618')+'/metrics', timeout=4)" \
    || exit 1

ENTRYPOINT ["ise-exporter"]
