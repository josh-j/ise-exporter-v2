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
STATE_DIR=/var/lib/ise-exporter
SHARED_STATE_DIR="$STATE_DIR/shared"
CONFIG_FILE="$CONFIG_DIR/config.toml"
SERVICE_USER=ise-exporter
SERVICE_NAME=ise-exporter
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
CLI_LINK=/usr/local/bin/ise-cli
PWSH_CLI_DIR="$INSTALL_DIR/powershell"
PWSH_MODULE_LINK=/usr/local/share/powershell/Modules/Ise.Cli/2.0.0
REVISION_FILE="$INSTALL_DIR/REVISION"
SERVICE_INSTALLED_BEFORE=0
if [[ -f "$UNIT_PATH" ]]; then
    SERVICE_INSTALLED_BEFORE=1
fi

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
# Debian and Ubuntu mark their system Python as externally managed. Keep it intact:
# install only distribution packages with apt and put all PyPI dependencies in the
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
# root:ise-exporter and group-readable so the service account can load TOML for
# both normal startup and manual preflight diagnostics.
echo "==> ensuring directories"
# Package code is not secret and must be traversable by every local user so the
# /usr/local/bin/ise-cli entrypoint works. Configuration and certificates remain
# restricted to root + the service group.
install -d -o root -g root -m 755 "$INSTALL_DIR"
install -d -o root -g "$SERVICE_USER" -m 750 "$CONFIG_DIR" "$CERTS_DIR"
# The private SQLite cache stays in a non-writable parent. Only the dedicated
# pacing subdirectory is group-writable for authorized interactive CLI users.
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$STATE_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 2770 "$SHARED_STATE_DIR"

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

# Preserve exact source identity without adding Git as a production prerequisite.
# A real checkout contributes its commit; an archive remains honestly unknown
# unless the packaging caller supplies a bounded revision explicitly.
BUILD_REVISION="${ISE_EXPORTER_BUILD_REVISION:-}"
if [[ ! "$BUILD_REVISION" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
    BUILD_REVISION=""
fi
if [[ -z "$BUILD_REVISION" ]] && command -v git >/dev/null 2>&1 \
        && git -C "$SOURCE_DIR" rev-parse --verify HEAD >/dev/null 2>&1; then
    BUILD_REVISION="$(git -C "$SOURCE_DIR" rev-parse --short=12 HEAD)"
    if [[ -n "$(git -C "$SOURCE_DIR" status --porcelain --untracked-files=normal)" ]]; then
        BUILD_REVISION="${BUILD_REVISION}-dirty"
    fi
fi
BUILD_REVISION="${BUILD_REVISION:-unknown}"
printf '%s\n' "$BUILD_REVISION" >"$REVISION_FILE"
chown root:root "$REVISION_FILE"
chmod 644 "$REVISION_FILE"
echo "==> build revision: $BUILD_REVISION"

# PowerShell 7 operator module and global launcher. The private Python entrypoint
# remains the bounded transport/query backend; operators receive native objects,
# pipeline behavior, help, and completion from Ise.Cli.
echo "==> installing global read-only CLI at $CLI_LINK"
rm -rf "$PWSH_CLI_DIR"
install -d -o root -g root -m 755 "$PWSH_CLI_DIR"
cp -a "$SOURCE_DIR/powershell/." "$PWSH_CLI_DIR/"
chown -R root:root "$PWSH_CLI_DIR"
chmod -R go-w "$PWSH_CLI_DIR"
chmod -R a+rX "$PWSH_CLI_DIR"
install -d -o root -g root -m 755 "$(dirname "$PWSH_MODULE_LINK")"
rm -rf "$PWSH_MODULE_LINK"
ln -s "$PWSH_CLI_DIR/Ise.Cli" "$PWSH_MODULE_LINK"
install -d -o root -g root -m 755 "$(dirname "$CLI_LINK")"
ln -sfn "$PWSH_CLI_DIR/ise-cli" "$CLI_LINK"
if ! command -v pwsh >/dev/null 2>&1; then
    echo "==> WARNING: PowerShell 7 (pwsh) is not installed; exporter service is ready,"
    echo "    but $CLI_LINK requires pwsh before operators can use Ise.Cli"
fi

# --- config: seed once, never overwrite on upgrade ---------------------
FRESH_CONFIG=0
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "==> no existing config — seeding $CONFIG_FILE"
    cp "$SOURCE_DIR/ise-exporter.toml.example" "$CONFIG_FILE"
    FRESH_CONFIG=1
else
    echo "==> existing config found at $CONFIG_FILE — leaving it untouched"
fi
chown root:"$SERVICE_USER" "$CONFIG_FILE"
chmod 640 "$CONFIG_FILE"
chown root:"$SERVICE_USER" "$CERTS_DIR"
chmod 750 "$CERTS_DIR"
# Any certificate/key files already dropped in $CERTS_DIR by a previous run:
# re-assert ownership without touching content. PEM is deliberately treated as
# private because the extension does not distinguish a certificate from a key.
if compgen -G "$CERTS_DIR"'/*' > /dev/null; then
    chown root:"$SERVICE_USER" "$CERTS_DIR"/*
    chmod 640 "$CERTS_DIR"/*
    chmod 644 "$CERTS_DIR"/*.cer "$CERTS_DIR"/*.crt 2>/dev/null || true
fi

# --- systemd unit -------------------------------------------------------
echo "==> installing systemd unit"
cp "$SOURCE_DIR/deploy/ise-exporter.service" "$UNIT_PATH"
systemctl daemon-reload

# --- lifecycle -------------------------------------------------------
# A newly seeded TOML file intentionally contains documentation
# placeholders. Never start (or restart) a network client with those values: a
# systemd restart loop would repeatedly try the example hosts and credentials.
PLACEHOLDER_CONFIG=0
if grep -Eq \
    '^[[:space:]]*(host[[:space:]]*=[[:space:]]*"(pan1|mnt1)\.example\.com"|password[[:space:]]*=[[:space:]]*"changeme")[[:space:]]*$' \
    "$CONFIG_FILE"; then
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
    echo "==> WARNING: placeholder values remain in $CONFIG_FILE; service will not be started"
    # A configuration-management system may stage the TOML file before the
    # package/unit exists. The service should still participate in normal boot
    # once the operator replaces the placeholders and starts it deliberately.
    if [[ "$SERVICE_INSTALLED_BEFORE" -eq 0 ]]; then
        echo "==> enabling $SERVICE_NAME without starting it (configuration required)"
        systemctl enable "$SERVICE_NAME"
    fi
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "==> stopping $SERVICE_NAME so placeholder credentials cannot be retried"
        systemctl stop "$SERVICE_NAME"
    fi
elif [[ "$SERVICE_INSTALLED_BEFORE" -eq 0 ]]; then
    echo "==> enabling and starting $SERVICE_NAME (pre-staged configuration)"
    systemctl enable --now "$SERVICE_NAME"
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
    echo "    1. sudoedit $CONFIG_FILE"
    echo "    2. install the Data Connect CA chain under $CERTS_DIR"
    echo "    3. sudo -u $SERVICE_USER $INSTALL_DIR/.venv/bin/$SERVICE_NAME --dataconnect-check"
    echo "    4. sudo systemctl start $SERVICE_NAME"
    echo "    5. sudo systemctl status $SERVICE_NAME"
elif [[ "$PLACEHOLDER_CONFIG" -eq 1 ]]; then
    echo "==> Replace every example/changeme value, run --dataconnect-check, then start the service."
fi
