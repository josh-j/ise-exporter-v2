# Build the wheel in a throwaway stage so the runtime image carries no build tools.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY ise_exporter ./ise_exporter
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="ise-exporter" \
      org.opencontainers.image.description="Prometheus exporter for Cisco ISE" \
      org.opencontainers.image.version="2.0.0"
WORKDIR /app
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
RUN install -d -o 65534 -g 65534 -m 750 /var/lib/ise-exporter

EXPOSE 9618
# run as nobody:nogroup; only /var/lib/ise-exporter is writable for the endpoint cache
USER 65534:65534

# honors EXPORTER_PORT; hits the metrics endpoint to confirm the server is up
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request; \
urllib.request.urlopen('http://127.0.0.1:'+os.getenv('EXPORTER_PORT','9618')+'/metrics', timeout=4)" \
    || exit 1

ENTRYPOINT ["ise-exporter"]
