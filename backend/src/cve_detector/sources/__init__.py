"""Vulnerability sources. OSV.dev is the only one for now."""

from cve_detector.core.config import Settings
from cve_detector.sources.base import VulnSource
from cve_detector.sources.osv import OsvSource


def make_sources(settings: Settings) -> list[VulnSource]:
    return [
        OsvSource(
            base_url=settings.osv_api_url,
            timeout=settings.http_timeout_seconds,
            max_workers=settings.osv_max_workers,
        )
    ]
