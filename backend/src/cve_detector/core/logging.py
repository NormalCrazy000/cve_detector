"""Logging setup."""

import logging


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    # One INFO line per HTTP request is too much; our sources log a summary instead.
    for name in ("httpx2", "httpcore2", "httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
