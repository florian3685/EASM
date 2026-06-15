"""
EASM Scanner — Checkpoint Persistence
========================================
Saves partial scan results so an aborted scan (Ctrl+C, crash, network drop)
can be resumed without redoing completed modules.

Layout:
    results/<domain>/checkpoint.json    ← rewritten atomically as scan progresses
                                           Removed once the final report is generated.

Strategy:
    - After each module completes → full snapshot
    - Inside Module 11 (long-running): after each Phase-1 endpoint → snapshot
    - Atomic write via tmp-file + rename so a Ctrl+C mid-write can't corrupt it
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from utils import get_logger

log = get_logger("easm.checkpoint")


class Checkpoint:
    """Persist partial scan results to results/<domain>/checkpoint.json."""

    SCHEMA_VERSION = 1

    def __init__(self, domain: str, outdir: str = "results"):
        self.domain = domain
        self.dir = Path(outdir) / domain
        self.path = self.dir / "checkpoint.json"
        self.dir.mkdir(parents=True, exist_ok=True)

    # ── lifecycle ────────────────────────────────────────────────────────

    def exists(self) -> bool:
        return self.path.is_file()

    def age_hours(self) -> float:
        """Age of the checkpoint in hours (0.0 if missing)."""
        if not self.exists():
            return 0.0
        delta = datetime.now().timestamp() - self.path.stat().st_mtime
        return delta / 3600.0

    def load(self) -> Optional[dict]:
        """Return saved state, or None if missing/corrupt."""
        if not self.exists():
            return None
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "results" not in data:
                log.warning(f"Checkpoint at {self.path} has unexpected shape — ignoring")
                return None
            return data
        except (json.JSONDecodeError, OSError) as exc:
            log.warning(f"Checkpoint at {self.path} unreadable ({exc}) — ignoring")
            return None

    def save(self, results: dict, completed_modules: list[int],
             current_module: Optional[int] = None,
             phase: Optional[str] = None) -> None:
        """Atomically write a snapshot."""
        data = {
            "_meta": {
                "schema": self.SCHEMA_VERSION,
                "domain": self.domain,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "completed_modules": sorted(set(completed_modules)),
                "current_module": current_module,
                "phase": phase,
            },
            "results": results,
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError as exc:
            log.error(f"Failed to save checkpoint: {exc}")
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass

    def clear(self) -> None:
        """Remove the checkpoint (call after final report is written)."""
        try:
            if self.path.exists():
                self.path.unlink()
                log.debug(f"Checkpoint cleared: {self.path}")
        except OSError as exc:
            log.debug(f"Could not delete checkpoint {self.path}: {exc}")
