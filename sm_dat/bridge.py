"""Adapter from sm-dat's rich verifier to sm-arp's ``dat_verifier`` hook.

``sm_arp.verify_authority_chain(receipt, grants, *, dats=, dat_verifier=)`` (sm-arp
>= 0.3.0) resolves a referenced DAT and delegates the rich evaluation to an
injected callback. sm-arp cannot import sm-dat (dependency direction), so sm-dat
supplies the callback. This builds it.

The verdict spaces differ: sm-dat is three-valued
(SATISFIED / VIOLATED / INDETERMINATE); sm-arp's ``VerifyResult`` is binary. The
mapping is **fail-closed** — SATISFIED → ok; both VIOLATED and INDETERMINATE →
not ok, with ``"<status>:<reason>"`` preserved in ``detail`` so a caller can still
tell an INDETERMINATE (couldn't decide) from a VIOLATED (decided no). This is the
honest collapse: sm-arp's chain check can only pass what sm-dat could positively
vouch for.
"""

from __future__ import annotations

from typing import Any, Callable

from sm_arp import VerifyResult

from .ledger import LedgerContext
from .verify import SATISFIED, verify_grant


def make_dat_verifier(
    *,
    ledger_contexts: dict[str, LedgerContext] | None = None,
    revocation_checker: Callable[[str, str], bool | None] | None = None,
    predicate_evaluator: Callable[[str, dict[str, Any], dict[str, Any]], bool] | None = None,
) -> Callable[[dict[str, Any], dict[str, Any]], VerifyResult]:
    """Return a ``dat_verifier(dat, receipt) -> VerifyResult`` for
    ``sm_arp.verify_authority_chain``. Optional per-grant ledger contexts (keyed
    by ``grant_id``), a revocation checker, and a predicate evaluator are closed
    over and passed through to :func:`verify_grant`."""
    ledgers = ledger_contexts or {}

    def _verify(dat: dict[str, Any], receipt: dict[str, Any]) -> VerifyResult:
        principal = receipt.get("principal_did")
        if not isinstance(principal, str) or not principal or dat.get("grantor_did") != principal:
            return VerifyResult(False, "authority_chain", "violated:grantor_mismatch")
        verdict = verify_grant(
            dat,
            receipt["action"],
            receipt["issued_at"],
            agent_did=receipt.get("issuer_did"),
            receipt_id=receipt.get("receipt_id") or "",
            ledger_context=ledgers.get(dat.get("grant_id", "")),
            revocation_checker=revocation_checker,
            predicate_evaluator=predicate_evaluator,
        )
        if verdict.status == SATISFIED:
            return VerifyResult.accepted()
        # VIOLATED or INDETERMINATE → fail closed; preserve the rich reason.
        return VerifyResult(False, "authority_chain", f"{verdict.status.lower()}:{verdict.reason}")

    return _verify
