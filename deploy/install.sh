#!/usr/bin/env bash
# Idempotent install/upgrade for the systemd deployment of ise-exporter.
# Fresh install: creates the service user, directories, venv, config skeleton,
# and systemd unit, then starts the service.
# Upgrade: re-run from an updated checkout — reuses the existing user/dirs/config,
# upgrades the package in place, refreshes the unit file, and restarts.
#
# Usage: sudo ./deploy/install.sh [path-to-repo-checkout]
#   (defaults to the repo this script lives in)
set -euo pipefail

SOURCE_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
INSTALL_DIR=/opt/ise-exporter
CONFIG_DIR=/etc/ise-exporter
CERTS_DIR="$CONFIG_DIR/certs"
ENV_FILE="$CONFIG_DIR/ise-exporter.env"
SERVICE_USER=ise-exporter
SERVICE_NAME=ise-exporter
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
CLI_LINK=/usr/local/bin/ise-cli

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0 [path-to-repo-checkout]" >&2
    exit 1
fi

if [[ ! -f "$SOURCE_DIR/pyproject.toml" ]] || [[ ! -f "$SOURCE_DIR/deploy/ise-exporter.service" ]]; then
    echo "error: $SOURCE_DIR doesn't look like an ise-exporter checkout (no pyproject.toml / deploy/ise-exporter.service)" >&2
    exit 1
fi

echo "==> source: $SOURCE_DIR"

# --- native host prerequisites -------------------------------------------
# Ubuntu 24.04 marks its system Python as externally managed. Keep it intact:
# install only Ubuntu packages with apt and put all PyPI dependencies in the
# dedicated /opt venv below. python-oracledb runs in thin mode, so Data Connect
# does not require Oracle Instant Client or any third-party apt repository.
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]]; then
        echo "==> detected Ubuntu 24.04 LTS (Noble Numbat)"
    else
        echo "==> detected ${PRETTY_NAME:-unknown Linux distribution}"
    fi
fi

if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then
    REQUIRED_APT_PACKAGES=(python3 python3-venv ca-certificates)
    MISSING_APT_PACKAGES=()
    for package in "${REQUIRED_APT_PACKAGES[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
            MISSING_APT_PACKAGES+=("$package")
        fi
    done
    if (( ${#MISSING_APT_PACKAGES[@]} )); then
        echo "==> installing standard OS prerequisites: ${MISSING_APT_PACKAGES[*]}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends "${MISSING_APT_PACKAGES[@]}"
    else
        echo "==> standard OS prerequisites already installed"
    fi
fi

for command_name in python3 useradd install systemctl; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "error: required command not found: $command_name" >&2
        echo "install Python 3.10+, venv, CA certificates, passwd, coreutils, and systemd" >&2
        exit 1
    fi
done

if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    echo "error: ise-exporter requires Python 3.10 or newer" >&2
    exit 1
fi

# --- service account -------------------------------------------------------
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "==> creating system user $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
    echo "==> user $SERVICE_USER already exists"
fi

# --- directories -------------------------------------------------------
# root:ise-exporter, group-readable rather than root-only: EnvironmentFile= is read
# by systemd (root) before it drops privileges, so root-only would work for the
# service itself, but group-read also lets `sudo -u ise-exporter ise-exporter
# --dataconnect-check` read the file directly for manual diagnostics.
echo "==> ensuring directories"
# Package code is not secret and must be traversable by every local user so the
# /usr/local/bin/ise-cli entrypoint works. Configuration and certificates remain
# restricted to root + the service group.
install -d -o root -g root -m 755 "$INSTALL_DIR"
install -d -o root -g "$SERVICE_USER" -m 750 "$CONFIG_DIR" "$CERTS_DIR"

# --- venv + package (install or upgrade in place) ---------------------
VENV="$INSTALL_DIR/.venv"
# Recreate a venv that's missing OR broken — one left from a different python3, a
# partial earlier run, or whose interpreter no longer executes. A healthy venv is
# reused for an in-place upgrade.
if [[ -d "$VENV" ]] && ! "$VENV/bin/python" -c 'import sys' &>/dev/null; then
    echo "==> existing venv at $VENV is broken/incompatible — recreating"
    rm -rf "$VENV"
fi
if [[ ! -d "$VENV" ]]; then
    echo "==> creating venv at $VENV"
    python3 -m venv "$VENV"
else
    echo "==> reusing existing venv at $VENV"
fi
echo "==> installing/upgrading ise-exporter from $SOURCE_DIR"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q --upgrade "$SOURCE_DIR"
# Own the venv root:ise-exporter (NOT root:root): the service runs as
# User/Group=ise-exporter and must READ+EXECUTE the interpreter, but not be able to
# modify its own code (owner stays root, no non-root user gets write). chmod a+rX
# makes the installed read-only CLI executable for every local user regardless of
# the admin's umask. Applied every run, so it repairs older group-only installs too.
chown -R root:"$SERVICE_USER" "$VENV"
chmod -R go-w "$VENV"
chmod -R a+rX "$VENV"
INSTALLED_VERSION="$("$VENV/bin/python" -c \
    "import importlib.metadata as m; print(m.version('ise-exporter'))")"
echo "==> installed ise-exporter $INSTALLED_VERSION"

# Global read-only operator CLI. The target remains root-owned in the venv; this
# symlink only makes it discoverable on every user's normal PATH.
echo "==> installing global read-only CLI at $CLI_LINK"
install -d -o root -g root -m 755 "$(dirname "$CLI_LINK")"
ln -sfn "$VENV/bin/ise-cli" "$CLI_LINK"

# --- config: seed once, never overwrite on upgrade ---------------------
FRESH_CONFIG=0
if [[ ! -f "$ENV_FILE" ]]; then
    echo "==> no existing config — seeding $ENV_FILE from .env.example"
    cp "$SOURCE_DIR/.env.example" "$ENV_FILE"
    FRESH_CONFIG=1
else
    echo "==> existing config found at $ENV_FILE — leaving it untouched"
fi
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"
chown root:"$SERVICE_USER" "$CERTS_DIR"
chmod 750 "$CERTS_DIR"
# any cert/key files already dropped in $CERTS_DIR by a previous run — re-assert
# ownership without touching content, and keep the private key tighter than certs.
if compgen -G "$CERTS_DIR"'/*' > /dev/null; then
    chown root:"$SERVICE_USER" "$CERTS_DIR"/*
    chmod 644 "$CERTS_DIR"/*.cer "$CERTS_DIR"/*.pem 2>/dev/null || true
    chmod 640 "$CERTS_DIR"/*.key 2>/dev/null || true
fi

# --- systemd unit -------------------------------------------------------
echo "==> installing systemd unit"
cp "$SOURCE_DIR/deploy/ise-exporter.service" "$UNIT_PATH"
systemctl daemon-reload

# --- lifecycle -------------------------------------------------------
# A newly seeded EnvironmentFile intentionally contains documentation
# placeholders. Never start (or restart) a network client with those values: a
# systemd restart loop would repeatedly try the example hosts and credentials.
PLACEHOLDER_CONFIG=0
if grep -Eq \
    '^(ISE_HOST=pan1\.example\.mil|ISE_MNT_HOST=mnt1\.example\.mil|ISE_PASS=changeme|ISE_DATACONNECT_HOST=mnt1\.example\.mil|ISE_DATACONNECT_PASSWORD=changeme)$' \
    "$ENV_FILE"; then
    PLACEHOLDER_CONFIG=1
fi

if [[ "$FRESH_CONFIG" -eq 1 ]]; then
    echo "==> enabling $SERVICE_NAME without starting it (configuration required)"
    systemctl enable "$SERVICE_NAME"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "==> stopping $SERVICE_NAME so sample credentials cannot be retried"
        systemctl stop "$SERVICE_NAME"
    fi
elif [[ "$PLACEHOLDER_CONFIG" -eq 1 ]]; then
    echo "==> WARNING: placeholder values remain in $ENV_FILE; service will not be started"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "==> stopping $SERVICE_NAME so placeholder credentials cannot be retried"
        systemctl stop "$SERVICE_NAME"
    fi
elif systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "==> restarting active $SERVICE_NAME (upgrade)"
    systemctl restart "$SERVICE_NAME"
else
    echo "==> $SERVICE_NAME is inactive; preserving operator-selected stopped state"
fi

sleep 1
systemctl --no-pager --lines=0 status "$SERVICE_NAME" || true

echo
echo "==> done — installed version $INSTALLED_VERSION"
echo "==> logs: journalctl -u $SERVICE_NAME -f"
echo "==> read-only CLI: $CLI_LINK --help"
echo "==> Data Connect check (run as the service user so it reads deployed config):"
echo "    sudo -u $SERVICE_USER $INSTALL_DIR/.venv/bin/$SERVICE_NAME --dataconnect-check"
if [[ "$FRESH_CONFIG" -eq 1 ]]; then
    echo "==> NOTE: fresh installation is enabled but intentionally NOT running. Next steps:"
    echo "    1. sudoedit $ENV_FILE"
    echo "    2. install the Data Connect CA chain under $CERTS_DIR"
    echo "    3. sudo -u $SERVICE_USER $INSTALL_DIR/.venv/bin/$SERVICE_NAME --dataconnect-check"
    echo "    4. sudo systemctl start $SERVICE_NAME"
    echo "    5. sudo systemctl status $SERVICE_NAME"
elif [[ "$PLACEHOLDER_CONFIG" -eq 1 ]]; then
    echo "==> Replace every example/changeme value, run --dataconnect-check, then start the service."
fi
