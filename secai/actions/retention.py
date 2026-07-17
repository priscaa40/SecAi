from __future__ import annotations

import logging
import threading

from secai.database.maintenance import purge_expired_data
from secai.settings import get_settings

logger = logging.getLogger(__name__)
_stop_event = threading.Event()
_worker: threading.Thread | None = None


def start_retention_worker() -> None:
    """Start periodic cleanup of expired security and authentication records."""
    global _worker
    if get_settings().secai_retention_interval_seconds <= 0 or (_worker and _worker.is_alive()):
        return
    _stop_event.clear()
    _worker = threading.Thread(target=_retention_loop, name="secai-retention", daemon=True)
    _worker.start()


def stop_retention_worker() -> bool:
    _stop_event.set()
    if _worker and _worker.is_alive():
        _worker.join(timeout=5)
    return not bool(_worker and _worker.is_alive())


def _retention_loop() -> None:
    interval = max(300, get_settings().secai_retention_interval_seconds)
    while not _stop_event.wait(interval):
        try:
            purge_expired_data()
        except Exception:
            logger.exception("SecAi retention cleanup failed")
