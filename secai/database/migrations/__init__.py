from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secai.database.migrations import v003_to_v004, v004_to_v005, v005_to_v006, v006_to_v007, v007_to_v008

Migration = Callable[[Any], None]

MIGRATIONS: dict[int, Migration] = {
    3: v003_to_v004.apply,
    4: v004_to_v005.apply,
    5: v005_to_v006.apply,
    6: v006_to_v007.apply,
    7: v007_to_v008.apply,
}


def migrate(conn: Any, found_version: int, target_version: int) -> None:
    """Apply each required one-way migration inside the startup transaction."""
    if found_version > target_version:
        raise RuntimeError(
            f"SecAi database schema {found_version} is newer than this release, which requires schema {target_version}."
        )
    current = found_version
    while current < target_version:
        migration = MIGRATIONS.get(current)
        if not migration:
            raise RuntimeError(
                f"No SecAi database migration exists from schema {current} to {current + 1}."
            )
        migration(conn)
        current += 1
        conn.execute("update schema_metadata set version = ? where singleton = 1", (current,))
