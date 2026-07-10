"""patches collector (port of collect_patch_metrics). Installed-patch inventory +
ISE version via PAN OpenAPI: highest patch number, per-patch installed flag,
version Info."""
import logging

from .. import metrics
from ..util import clear_metric
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)


def collect(client, cfg, mappings):
    with observe("patches"):
        patches = client.get_pan_api("/patch", api_name="pan_patches")
        if not patches:
            raise CollectorFailed("no patch info returned")

        version = patches.get("iseVersion", "unknown")
        metrics.ise_version_info.info({"version": version})

        clear_metric(metrics.ise_patch_installed)
        max_patch = 0
        for patch in patches.get("patchVersion", []):
            try:                                  # ISE sends an int; tolerate null/str
                num = int(patch.get("patchNumber", 0) or 0)
            except (TypeError, ValueError):
                num = 0
            metrics.ise_patch_installed.labels(patch_number=str(num)).set(1)
            max_patch = max(max_patch, num)
        metrics.ise_patch_level.set(max_patch)
        logger.info("Patches: ISE %s, patch level %d", version, max_patch)
