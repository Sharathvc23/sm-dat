"""Minimal revocation checking (SPEC §7).

A grantor publishes a signed list of revoked grant_ids. A verifier treats a grant
as revoked iff an entry with ``revoked_at <= action.issued_at`` exists, and the
list is fresher than ``max_revocation_age_seconds``. A stale/absent list yields
None → INDETERMINATE upstream, never an implicit pass.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _t(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


class StaticRevocationList:
    """In-memory revocation list, the shape a ``revocation_lookup_uri`` returns.

    ``entries``: ``[{"grant_id", "revoked_at", "reason"?}, ...]``.
    ``fetched_at``: when this list was retrieved (freshness clock).
    """

    def __init__(self, entries: list[dict[str, Any]], *, fetched_at: str, max_age_seconds: int = 86400):
        self.by_id = {e["grant_id"]: e for e in entries}
        self.fetched_at = _t(fetched_at)
        self.max_age = max_age_seconds

    def __call__(self, grant_id: str, issued_at: str) -> bool | None:
        as_of = _t(issued_at)
        # Freshness is measured against the action's time, not wall-clock, so the
        # check is deterministic and replayable.
        if (as_of - self.fetched_at).total_seconds() > self.max_age:
            return None  # stale → INDETERMINATE
        entry = self.by_id.get(grant_id)
        if entry is None:
            return False  # known live
        return _t(entry["revoked_at"]) <= as_of
