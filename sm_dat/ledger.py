"""LedgerContext — the prior-receipt accounting a verifier needs to evaluate
*stateful* (per-period) constraints (SPEC §4.2).

The sm_arp store (`ReceiptLog`/`AgencyLog`) only `append`s; it has no
query-by-grant API. So LedgerContext takes the receipts in memory and filters
them itself. `from_receipts` is the adapter; an upstream `ReceiptLog.by_grant`
would slot in here later without changing callers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _window_start(as_of: datetime, period: str, anchor: str) -> datetime:
    """Return the lower bound (inclusive) of the accounting window containing
    ``as_of``. The upper bound is ``as_of`` itself under the total order (§4.2)."""
    if anchor == "rolling":
        span = {"day": timedelta(days=1), "week": timedelta(weeks=1), "month": timedelta(days=30)}[period]
        return as_of - span
    # calendar anchor
    if period == "day":
        return as_of.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "week":
        return (as_of - timedelta(days=as_of.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "month":
        return as_of.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"unknown period {period!r}")


class LedgerContext:
    """Prior actions that cited a given grant. Each entry:
    ``{issued_at, amount_cents, currency}``."""

    def __init__(self, entries: Iterable[dict[str, Any]]):
        self.entries = list(entries)

    @classmethod
    def from_receipts(cls, receipts: Iterable[dict[str, Any]], grant_id: str) -> "LedgerContext":
        """Filter receipts whose ``authority_chain`` cites ``grant_id`` and pull
        their amount + timestamp."""
        out = []
        for r in receipts:
            if grant_id not in (r.get("authority_chain") or []):
                continue
            amt = (r.get("action") or {}).get("amount") or {}
            out.append({
                "issued_at": r.get("issued_at"),
                "receipt_id": r.get("receipt_id") or "",
                "amount_cents": amt.get("cents"),
                "currency": amt.get("currency"),
            })
        return cls(out)

    def period_sum(self, *, period: str, anchor: str, as_of: str, currency: str,
                   as_of_receipt_id: str = "") -> int:
        """Sum amount_cents of entries that (a) fall in the period window and
        (b) strictly precede the action under test in the total order
        ``(issued_at, receipt_id)`` — SPEC §4.2. Excludes the action itself
        (caller adds it). Same-``issued_at`` peers are ordered by ``receipt_id``
        ascending, so the sum is deterministic regardless of insertion order."""
        as_of_dt = _parse(as_of)
        lo = _window_start(as_of_dt, period, anchor)
        here = (as_of_dt, as_of_receipt_id or "")
        total = 0
        for e in self.entries:
            if e.get("currency") != currency or not isinstance(e.get("amount_cents"), int):
                continue
            t = _parse(e["issued_at"])
            if t < lo:
                continue
            if (t, e.get("receipt_id") or "") < here:   # strictly prior in total order
                total += e["amount_cents"]
        return total
