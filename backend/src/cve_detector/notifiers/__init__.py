"""Notification channels. Email is the only one for now."""

from cve_detector.core.config import Settings
from cve_detector.notifiers.base import Notifier
from cve_detector.notifiers.smtp import EmailNotifier


def make_notifiers(settings: Settings) -> dict[str, Notifier]:
    """The configured channels by name; unconfigured channels are left out."""
    notifiers: dict[str, Notifier] = {}
    if email := EmailNotifier.from_settings(settings):
        notifiers[email.channel] = email
    return notifiers
