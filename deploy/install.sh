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
# --pxgrid-check` read the file directly via load_dotenv() for manual diagnostics.
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
    chmod 644 "$CERTS_DIR"/*.cer 2>/dev/null || true
    chmod 640 "$CERTS_DIR"/*.key 2>/dev/null || true
fi

# --- systemd unit -------------------------------------------------------
echo "==> installing systemd unit"
cp "$SOURCE_DIR/deploy/ise-exporter.service" "$UNIT_PATH"
systemctl daemon-reload

# --- (re)start -------------------------------------------------------
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "==> restarting $SERVICE_NAME (upgrade)"
    systemctl restart "$SERVICE_NAME"
else
    echo "==> enabling + starting $SERVICE_NAME (fresh install)"
    systemctl enable --now "$SERVICE_NAME"
fi

sleep 1
systemctl --no-pager --lines=0 status "$SERVICE_NAME" || true

echo
echo "==> done — installed version $INSTALLED_VERSION"
echo "==> logs: journalctl -u $SERVICE_NAME -f"
echo "==> read-only CLI: $CLI_LINK --help"
echo "==> pxGrid check (run as the service user so it can read the config + certs):"
echo "    sudo -u $SERVICE_USER $INSTALL_DIR/.venv/bin/$SERVICE_NAME --pxgrid-check"
if [[ "$FRESH_CONFIG" -eq 1 ]]; then
    echo "==> NOTE: this was a fresh install — edit $ENV_FILE (ISE_HOST/ISE_MNT_HOST/ISE_USER/ISE_PASS"
    echo "    and, if using pxGrid, PXGRID_* + certs under $CERTS_DIR), then:"
    echo "    sudo systemctl restart $SERVICE_NAME"
fi
