"""Prometheus exporter for Cisco ISE."""
import os
import re
from pathlib import Path


__version__ = "2.0.0"
SUPPORTED_ISE_RELEASE = "3.3.0.430 Patch 11"
BUILD_REVISION_FILE = "/opt/ise-exporter/REVISION"


def build_revision():
    """Return one bounded package identity supplied by the deployment wrapper."""
    revision = os.environ.get("ISE_EXPORTER_BUILD_REVISION", "").strip()
    if not revision:
        try:
            with Path(BUILD_REVISION_FILE).open(encoding="ascii") as marker:
                revision = marker.read(65).strip()
                if marker.read(1):
                    return "unknown"
        except (OSError, UnicodeError):
            pass
    return revision if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", revision) else "unknown"


def version_string(program):
    return (f"{program} {__version__} (revision {build_revision()}; "
            f"Cisco ISE {SUPPORTED_ISE_RELEASE})")
