"""Notification channel interface."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Message:
    subject: str
    text: str
    html: str


@dataclass(frozen=True, slots=True)
class Delivery:
    """Outcome of sending one message to some targets of a channel."""

    targets: list[str]
    success: bool
    error: str | None = None


class Notifier(Protocol):
    channel: str

    def send(self, targets: list[str], message: Message, *, together: bool) -> list[Delivery]:
        """Send the message; ``together`` sends one message to all targets instead of one
        each. Never raises for delivery problems, they are reported as failed deliveries."""
        ...
