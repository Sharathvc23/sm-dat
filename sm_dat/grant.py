"""DAT envelope construction, signing, and signature verification.

Crypto is reused from ``sm_arp`` — JCS canonicalization, Ed25519, did:key — so a
DAT and an ARP receipt share the exact same signing path. The one difference:
a DAT is signed by the **grantor** (the principal), not the agent. See SPEC §8.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable

from sm_arp import Identity, canonical_bytes, now_iso, pubkey_from_did

DAT_VERSION = "dat/0.1"


def _parse_rfc3339(ts: Any) -> datetime | None:
    """Aware UTC datetime, or None when ``ts`` is not an RFC 3339 string with
    an offset. Mirrors ``sm_dat.verify.parse_rfc3339`` (which cannot be
    imported here without a cycle); the verifier is the normative copy."""
    if not isinstance(ts, str) or not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return None if d.tzinfo is None else d.astimezone(timezone.utc)


def build_grant(
    *,
    grantee_did: str,
    action_categories: Iterable[str],
    not_after: str,
    human_summary: str,
    not_before: str | None = None,
    stateless: dict[str, Any] | None = None,
    stateful: dict[str, Any] | None = None,
    predicate: str | None = None,
    parent_grant_id: str | None = None,
    max_depth: int = 4,
    revocation: dict[str, Any] | None = None,
    issued_at: str | None = None,
    grantor_did: str | None = None,
    grant_id: str | None = None,
    alt_summaries: list[dict[str, str]] | None = None,
    authorization_ceremony: dict[str, Any] | None = None,
    initial_bind: bool = False,
) -> dict[str, Any]:
    """Construct an unsigned DAT envelope (SPEC §3). Validates structure only;
    ``grantor_did`` and ``grant_id`` may be left None and are filled by
    :func:`sign_grant`. ``initial_bind=True`` permits an empty scope (SPEC §3.3)."""
    cats = list(action_categories)
    if not cats and not initial_bind:
        raise ValueError("action_categories must be non-empty")
    if len(human_summary) > 280:
        raise ValueError("human_summary exceeds 280 code points")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
        raise ValueError("max_depth must be a non-negative integer")
    nb = not_before or issued_at or now_iso()
    for name, ts in (("not_before", nb), ("not_after", not_after), ("issued_at", issued_at or nb)):
        if _parse_rfc3339(ts) is None:
            raise ValueError(f"{name} must be an RFC 3339 timestamp with a UTC offset: {ts!r}")
    grant: dict[str, Any] = {
        "version": DAT_VERSION,
        "grant_id": grant_id,
        "grantor_did": grantor_did,
        "grantee_did": grantee_did,
        "issued_at": issued_at or nb,
        "not_before": nb,
        "not_after": not_after,
        "human_summary": human_summary,
        "scope": {
            "action_categories": cats,
            "stateless": dict(stateless or {}),
            "stateful": dict(stateful or {}),
            "predicate": predicate,
        },
        "delegation": {"parent_grant_id": parent_grant_id, "max_depth": max_depth},
        "revocation": revocation,
        "authorization_ceremony": authorization_ceremony,
    }
    if alt_summaries:
        grant["alt_summaries"] = alt_summaries
    if initial_bind:
        grant["initial_bind"] = True
    return grant


def build_initial_bind(
    *,
    grantee_did: str,
    not_after: str,
    human_summary: str | None = None,
    not_before: str | None = None,
    issued_at: str | None = None,
    grantor_did: str | None = None,
) -> dict[str, Any]:
    """The implicit principal↔agent bind recorded at registration (SPEC §3.3).

    Fail-closed: its scope is empty, so it authorizes *nothing* requiring a DAT —
    it only attests that the binding exists. An action verified against an
    initial-bind grant alone is ``VIOLATED(initial_bind_authorizes_nothing)``,
    which a verifier can distinguish from "no grant at all" (no authority chain).
    """
    return build_grant(
        grantee_did=grantee_did,
        action_categories=[],
        not_after=not_after,
        human_summary=human_summary or "Initial bind: principal↔agent; authorizes nothing.",
        not_before=not_before,
        issued_at=issued_at,
        grantor_did=grantor_did,
        initial_bind=True,
    )


def sign_grant(grantor: Identity, grant: dict[str, Any]) -> dict[str, Any]:
    """Stamp ``grantor_did`` / ``grant_id`` (if absent) then Ed25519-sign the
    JCS-canonical envelope with the grantor's key (SPEC §8)."""
    g = {k: v for k, v in grant.items() if k != "signature"}
    g["grantor_did"] = grantor.did
    if not g.get("grant_id"):
        content = {k: v for k, v in g.items() if k != "grant_id"}
        digest = hashlib.sha256(canonical_bytes(content, include_signature=False)).hexdigest()[:16]
        g["grant_id"] = f"dat:{grantor.did}:{digest}"
    sig = grantor.sign(canonical_bytes(g, include_signature=False))
    g["signature"] = base64.b64encode(sig).decode("ascii")
    return g


def verify_grant_signature(grant: dict[str, Any]) -> bool:
    """True iff ``grant.signature`` verifies under ``grantor_did``'s key over the
    canonical envelope. Unlike ``sm_arp.verify_signature`` (which keys off
    ``issuer_did``), a DAT is keyed off ``grantor_did``."""
    try:
        pub = pubkey_from_did(grant["grantor_did"])
        sig = base64.b64decode(grant["signature"])
        pub.verify(sig, canonical_bytes(grant, include_signature=False))
        return True
    except Exception:  # noqa: BLE001 — any failure is a non-verifying signature
        return False
