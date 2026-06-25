"""The capability-gated predicate seam (SPEC §4.4).

A predicate is an optional, injected escape hatch. The library bundles no
evaluator; a caller supplies one (e.g. a CEL engine — see docs/predicate-annex.md).
Without one, a non-null predicate is INDETERMINATE — never a silent pass.
"""

from __future__ import annotations

from typing import Any

from sm_arp import build_action

from sm_dat import Identity, build_grant, sign_grant, verify_grant

P = Identity.from_seed(b"\x01" * 32)
A = Identity.from_seed(b"\x02" * 32)
WHEN = "2026-04-10T19:00:00Z"


def grant(pred: str) -> dict[str, Any]:
    return sign_grant(P, build_grant(
        grantee_did=A.did, action_categories=["purchase"], not_after="2026-12-31T23:59:59Z",
        not_before="2026-01-01T00:00:00Z", human_summary="purchase under a predicate",
        stateless={"amount_currency": "USD"}, predicate=pred))


def buy(cents: int) -> dict[str, Any]:
    return build_action(category="purchase", human_summary="x", amount_cents=cents, currency="USD")


def cents_lt_4000(_pred: str, _grant: dict[str, Any], action: dict[str, Any]) -> bool:
    """A tiny stand-in evaluator (a real one parses CEL). Pure, deterministic."""
    return (action.get("amount") or {}).get("cents", 0) < 4000


def test_no_evaluator_is_indeterminate():
    v = verify_grant(grant("action.amount.cents < 4000"), buy(3000), WHEN, agent_did=A.did)
    assert v.status == "INDETERMINATE" and v.reason == "predicate_unsupported"


def test_evaluator_true_satisfies():
    v = verify_grant(grant("action.amount.cents < 4000"), buy(3000), WHEN, agent_did=A.did,
                     predicate_evaluator=cents_lt_4000)
    assert v.status == "SATISFIED"


def test_evaluator_false_violates():
    v = verify_grant(grant("action.amount.cents < 4000"), buy(5000), WHEN, agent_did=A.did,
                     predicate_evaluator=cents_lt_4000)
    assert v.status == "VIOLATED" and v.reason == "predicate_failed"


def test_evaluator_that_raises_is_indeterminate_not_a_guess():
    def boom(_p: str, _g: dict[str, Any], _a: dict[str, Any]) -> bool:
        raise RuntimeError("evaluator exploded")

    v = verify_grant(grant("nonsense(("), buy(3000), WHEN, agent_did=A.did, predicate_evaluator=boom)
    assert v.status == "INDETERMINATE" and v.reason == "predicate_error"
