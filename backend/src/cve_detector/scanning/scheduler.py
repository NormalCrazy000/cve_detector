"""Background thread that runs due scans.

A single thread does all the scanning, so runs never overlap within the process
(the application is meant to run as one process). ``trigger`` wakes it up early,
e.g. after a "scan now" request; a request made during a run is served right after it.
"""

import logging
import threading
from collections.abc import Callable, Sequence
from datetime import timedelta

from sqlalchemy.orm import Session, sessionmaker

from cve_detector.db.models import ScanRun
from cve_detector.scanning.scan import (
    DEFAULT_EXPIRY_WARNING,
    DEFAULT_RETRY_AFTER,
    Notify,
    fail_interrupted_runs,
    run_scan,
)
from cve_detector.sources.base import VulnSource

logger = logging.getLogger(__name__)

# Called with every finished run, e.g. to alert the admin about failures.
AfterRun = Callable[[Session, ScanRun], None]


class Scheduler:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        sources: Sequence[VulnSource],
        *,
        tick_seconds: float = 300.0,
        retry_after: timedelta = DEFAULT_RETRY_AFTER,
        expiry_warning: timedelta = DEFAULT_EXPIRY_WARNING,
        notify: Notify | None = None,
        after_run: AfterRun | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._sources = list(sources)
        self._tick = tick_seconds
        self._retry_after = retry_after
        self._expiry_warning = expiry_warning
        self._notify = notify
        self._after_run = after_run
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("scheduler already started")
        with self._session_factory() as session:
            if interrupted := fail_interrupted_runs(session):
                logger.warning("%d scan runs were interrupted by a restart", interrupted)
        self._thread = threading.Thread(target=self._loop, name="scheduler", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 30.0) -> None:
        self._stopping.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def trigger(self) -> None:
        """Look for due projects now instead of at the next tick."""
        self._wake.set()

    def run_once(self) -> ScanRun | None:
        """Run a scan of the due projects; errors are logged, never raised."""
        try:
            with self._session_factory() as session:
                run = run_scan(
                    session,
                    self._sources,
                    notify=self._notify,
                    retry_after=self._retry_after,
                    expiry_warning=self._expiry_warning,
                )
                if run is not None and self._after_run is not None:
                    self._after_run(session, run)
                    session.commit()
                return run
        except Exception:
            logger.exception("scheduled scan crashed")
            return None

    def _loop(self) -> None:
        while not self._stopping.is_set():
            self._wake.clear()
            self.run_once()
            self._wake.wait(self._tick)
