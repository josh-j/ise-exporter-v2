"""patches collector (port of collect_patch_metrics). Installed-patch inventory +
ISE version via PAN OpenAPI: highest patch number, per-patch installed flag,
version Info."""
import logging

from .. import metrics
from ..compatibility import SUPPORTED_ISE_VERSION, SUPPORTED_PATCH_LEVEL
from ..snapshots import replace_metric_snapshot
from . import observe, CollectorFailed

logger = logging.getLogger(__name__)
_METRICS = (
    metrics.ise_version_info,
    metrics.ise_patch_level,
    metrics.ise_patch_installed,
)


def collect(client, cfg):
    with observe("patches"):
        patches = client.get_pan_api("/patch", api_name="pan_patches")
        if not patches:
            raise CollectorFailed("no patch info returned")
        if not isinstance(patches, dict):
            raise CollectorFailed("patch info response was not an object")
        version = str(patches.get("iseVersion") or "").strip()
        if version != SUPPORTED_ISE_VERSION:
            raise CollectorFailed(
                f"patch info reported unsupported ISE version {version!r}; "
                f"expected {SUPPORTED_ISE_VERSION}")
        patch_versions = patches.get("patchVersion", [])
        if patch_versions is None:
            patch_versions = []
        if not isinstance(patch_versions, list):
            raise CollectorFailed("patchVersion was not a list")

        installed = set()
        for patch in patch_versions:
            if not isinstance(patch, dict):
                raise CollectorFailed("patchVersion contained a non-object")
            try:                                  # ISE sends an int; tolerate null/str
                num = int(patch.get("patchNumber"))
            except (TypeError, ValueError) as error:
                raise CollectorFailed("patchVersion contained an invalid patch number") from error
            if num <= 0 or num > 999 or num in installed:
                raise CollectorFailed("patchVersion contained an invalid patch number")
            installed.add(num)
        max_patch = max(installed, default=0)
        if max_patch != SUPPORTED_PATCH_LEVEL:
            raise CollectorFailed(
                f"patch info reported unsupported patch level {max_patch}; "
                f"expected Patch {SUPPORTED_PATCH_LEVEL}")

        writers = [
            lambda: metrics.ise_version_info.info({"version": version}),
            lambda: metrics.ise_patch_level.set(max_patch),
        ]
        writers.extend(
            lambda num=num: metrics.ise_patch_installed.labels(
                patch_number=str(num)).set(1)
            for num in sorted(installed)
        )
        replace_metric_snapshot(_METRICS, writers)
        logger.info("Patches: ISE %s, patch level %d", version, max_patch)
