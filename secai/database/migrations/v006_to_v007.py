from __future__ import annotations

from typing import Any

from secai.database.migrations.v005_to_v006 import apply as normalize_reports


def apply(conn: Any) -> None:
    """Repair schema-6 reports that were missing part of the current report contract."""
    normalize_reports(conn)
