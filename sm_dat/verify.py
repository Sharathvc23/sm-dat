"""The verification decision procedure (SPEC §5–§6).

Three-valued by design: SATISFIED / VIOLATED / INDETERMINATE. The library never
collapses INDETERMINATE into pass or fail — that policy belongs to the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .grant import verify_grant_signature
from .ledger import LedgerContext

SATISFIED = "SATISFIED"
VIOLATED = "VIOLATED"
INDETERMINATE = "INDETERMINATE"

_REQUIRED = ("version", "grant_id", "grantor_did", "grantee_did", "issued_at",
             "not_before", "not_after", "human_summary", "scope", "signature")


@dataclass(frozen=True)
class Verdict:
    status: str           # SATISFIED | VIOLATED | INDETERMINATE
    reason: str           # machine reason code; "ok" when SATISFIED
    grant_id: str | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == SATISFIED


def _t(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def verify_grant(
    grant: dict[str, Any],
    action: dict[str, Any],
    issued_at: str,
    *,
    agent_did: str | None = None,
    receipt_id: str = "",
    ledger_context: LedgerContext | None = None,
    revocation_checker: Callable[[str, str], bool | None] | None = None,
    predicate_evaluator: Callable[[str, dict[str, Any], dict[str, Any]], bool] | None = None,
) -> Verdict:
    """Decide whether one DAT authorizes one action at ``issued_at`` (SPEC §5.1).

    ``revocation_checker(grant_id, issued_at)`` returns True if revoked, False if
    known-live, or None if it cannot tell (→ INDETERMINATE).
    """
    gid = grant.get("grant_id")

    def v(reason: str, detail: str = "") -> Verdict:
        return Verdict(VIOLATED, reason, gid, detail)

    def ind(reason: str, detail: str = "") -> Verdict:
        return Verdict(INDETERMINATE, reason, gid, detail)

    # 1. structure
    for f in _REQUIRED:
        if f not in grant:
            return v("malformed", f"missing {f!r}")
    if grant["version"] != "dat/0.1":
        return v("malformed", f"unexpected version {grant['version']!r}")
    if len(grant["human_summary"]) > 280:
        return v("malformed", "human_summary exceeds 280 code points")

    # 1a. self-grant — an agent cannot authorize itself. The literal
    # grantor==grantee case is rejected outright; the deeper case (grantor is a
    # second key the grantee secretly controls) is unsolvable by the library and
    # is a stated caller precondition (SPEC §3.2). Checked before signature so a
    # validly-signed self-grant still fails.
    if grant["grantor_did"] == grant["grantee_did"]:
        return v("self_grant", "grantor_did == grantee_did")

    # 2. signature
    if not verify_grant_signature(grant):
        return v("bad_signature")

    # 3. grantee
    if agent_did is not None and agent_did != grant["grantee_did"]:
        return v("grantee_mismatch", f"{agent_did} != {grant['grantee_did']}")

    # 4. temporal
    t = _t(issued_at)
    if t < _t(grant["not_before"]):
        return v("not_yet_valid")
    if t > _t(grant["not_after"]):
        return v("expired")

    # 5. revocation
    if grant.get("revocation") is not None:
        if revocation_checker is None:
            return ind("revocation_unknown", "no revocation_checker supplied")
        # grant_id is a required field validated in step 1, so it is present
        # here; read it directly (typed as the grant's value type) rather than
        # the pre-validation ``gid`` (Optional) so the str-typed checker call
        # type-checks.
        state = revocation_checker(grant["grant_id"], issued_at)
        if state is None:
            return ind("revocation_unknown", "checker could not resolve")
        if state:
            return v("revoked")

    scope = grant["scope"]

    # 5a. initial-bind authorizes nothing — it only attests the principal↔agent
    # binding exists (§3.3). Distinct reason so a verifier can tell it apart from
    # "no grant at all" (which surfaces as no_authority_chain).
    if grant.get("initial_bind"):
        return v("initial_bind_authorizes_nothing")

    # 6. category
    if action.get("category") not in scope["action_categories"]:
        return v("category_out_of_scope", str(action.get("category")))

    # 7. stateless constraints
    sl = scope.get("stateless") or {}
    amount = action.get("amount") or {}
    if "amount_cents_per_action_max" in sl:
        cur = sl.get("amount_currency")
        if cur is not None and amount.get("currency") != cur:
            return v("amount_currency_mismatch", f"{amount.get('currency')} != {cur}")
        cents = amount.get("cents")
        if not isinstance(cents, int):
            return v("amount_cap_exceeded", "action carries no amount to bound")
        if cents > sl["amount_cents_per_action_max"]:
            return v("amount_cap_exceeded", f"{cents} > {sl['amount_cents_per_action_max']}")
    allow = sl.get("counterparty_allowlist")
    if allow:
        cp = {action.get("counterparty_label"), action.get("counterparty_did")}
        if not (set(allow) & {c for c in cp if c}):
            return v("counterparty_not_allowed", str(cp))
    juris = sl.get("jurisdictions")
    if juris:
        aj = action.get("jurisdiction")
        if isinstance(aj, dict):
            aj = aj.get("region") or aj.get("code")
        if aj not in juris:
            return v("jurisdiction_not_allowed", str(aj))

    # 8. stateful constraints
    sf = scope.get("stateful") or {}
    if "amount_cents_per_period_max" in sf:
        if ledger_context is None:
            return ind("accounting_required", "per-period cap needs a ledger context")
        cur = sl.get("amount_currency") or amount.get("currency")
        if not isinstance(cur, str):
            return ind("accounting_required", "per-period amount cap requires a currency")
        prior = ledger_context.period_sum(
            period=sf["period"], anchor=sf.get("period_anchor", "calendar"),
            as_of=issued_at, as_of_receipt_id=receipt_id, currency=cur,
        )
        this = amount.get("cents") or 0
        if prior + this > sf["amount_cents_per_period_max"]:
            return v("period_cap_exceeded", f"{prior}+{this} > {sf['amount_cents_per_period_max']}")

    # 9. predicate (capability-gated). Without an injected evaluator the verdict
    # is INDETERMINATE — never a silent pass (§4.4). With one, a false predicate
    # is VIOLATED; an evaluator that raises is INDETERMINATE, not a guess.
    if scope.get("predicate") is not None:
        if predicate_evaluator is None:
            return ind("predicate_unsupported", "no predicate evaluator injected")
        try:
            passed = predicate_evaluator(scope["predicate"], grant, action)
        except Exception as e:  # noqa: BLE001 — an evaluator failure must not pass
            return ind("predicate_error", f"evaluator raised: {e}")
        if not passed:
            return v("predicate_failed", scope["predicate"])

    return Verdict(SATISFIED, "ok", gid)


def check_attenuation(child: dict[str, Any], parent: dict[str, Any]) -> Verdict:
    """A child grant's scope MUST be a subset of its parent's on every dimension
    (SPEC §6). Any widening ⇒ attenuation_breach."""
    cid = child.get("grant_id")
    cs, ps = child["scope"], parent["scope"]

    def breach(d: str) -> Verdict:
        return Verdict(VIOLATED, "attenuation_breach", cid, d)

    if not set(cs["action_categories"]) <= set(ps["action_categories"]):
        return breach("categories widen")
    csl, psl = cs.get("stateless") or {}, ps.get("stateless") or {}
    if "amount_cents_per_action_max" in psl:
        if csl.get("amount_cents_per_action_max", float("inf")) > psl["amount_cents_per_action_max"]:
            return breach("per-action cap widens")
    if psl.get("counterparty_allowlist"):
        if not set(csl.get("counterparty_allowlist") or []) <= set(psl["counterparty_allowlist"]):
            return breach("counterparty allowlist widens")
    if psl.get("jurisdictions"):
        if not set(csl.get("jurisdictions") or []) <= set(psl["jurisdictions"]):
            return breach("jurisdictions widen")
    csf, psf = cs.get("stateful") or {}, ps.get("stateful") or {}
    if "amount_cents_per_period_max" in psf:
        if csf.get("amount_cents_per_period_max", float("inf")) > psf["amount_cents_per_period_max"]:
            return breach("per-period cap widens")
    if _t(child["not_after"]) > _t(parent["not_after"]):
        return breach("not_after extends past parent")
    return Verdict(SATISFIED, "ok", cid)


def verify_authority_chain(
    receipt: dict[str, Any],
    grants: dict[str, dict[str, Any]],
    *,
    ledger_contexts: dict[str, LedgerContext] | None = None,
    revocation_checker: Callable[[str, str], bool | None] | None = None,
    predicate_evaluator: Callable[[str, dict[str, Any], dict[str, Any]], bool] | None = None,
) -> Verdict:
    """Aggregate over every grant in ``receipt.authority_chain`` (SPEC §5.3).

    AUTHORIZED iff at least one grant SATISFIED and none VIOLATED; any VIOLATED ⇒
    unauthorized; else any INDETERMINATE ⇒ INDETERMINATE. An ``initial_bind``
    grant is **neutral** — it attests the principal↔agent binding but neither
    authorizes nor blocks (§3.0), so the real grants decide; a chain with no
    authorizing grant (empty, or only initial-bind) is unauthorized. Also walks
    sub-delegation: each grant with a parent must attenuate it, bounded by
    ``max_depth``.
    """
    chain = receipt.get("authority_chain") or []
    ledger_contexts = ledger_contexts or {}
    pending_ind: Verdict | None = None
    authorizing = 0
    saw_initial_bind = False

    for gid in chain:
        grant = grants.get(gid)
        if grant is None:
            return Verdict(VIOLATED, "grant_not_found", gid)
        if grant.get("initial_bind"):
            # Neutral: never authorizes an action, never short-circuits to pass,
            # never blocks a real grant. The real grants decide (§3.0).
            saw_initial_bind = True
            continue

        # depth + attenuation along the parent links. Each ancestor is a
        # distinct signed grant, not just a data record referenced by id —
        # it MUST be independently signature-verified and MUST continue the
        # same delegation relationship as its child (child.grantor_did ==
        # parent.grantee_did), or the "chain" could silently splice in an
        # unrelated, unverified, or forged ancestor.
        depth, cur = 0, grant
        max_depth = (grant.get("delegation") or {}).get("max_depth", 4)
        while (cur.get("delegation") or {}).get("parent_grant_id"):
            parent_id = cur["delegation"]["parent_grant_id"]
            parent = grants.get(parent_id)
            if parent is None:
                return Verdict(VIOLATED, "grant_not_found", parent_id)
            if not verify_grant_signature(parent):
                return Verdict(VIOLATED, "bad_signature", parent_id, "ancestor grant")
            if cur.get("grantor_did") != parent.get("grantee_did"):
                return Verdict(
                    VIOLATED,
                    "chain_discontinuity",
                    parent_id,
                    f"child.grantor_did {cur.get('grantor_did')!r} != "
                    f"parent.grantee_did {parent.get('grantee_did')!r}",
                )
            att = check_attenuation(cur, parent)
            if not att.ok:
                return att
            depth += 1
            if depth > max_depth:
                return Verdict(VIOLATED, "depth_exceeded", gid, f"depth {depth} > {max_depth}")
            cur = parent

        verdict = verify_grant(
            grant, receipt["action"], receipt["issued_at"],
            agent_did=receipt.get("issuer_did"),
            receipt_id=receipt.get("receipt_id") or "",
            ledger_context=ledger_contexts.get(gid),
            revocation_checker=revocation_checker,
            predicate_evaluator=predicate_evaluator,
        )
        if verdict.status == VIOLATED:
            return verdict
        if verdict.status == INDETERMINATE:
            pending_ind = verdict
        else:
            authorizing += 1

    if pending_ind is not None:
        return pending_ind
    if authorizing == 0:
        # No grant actually authorized the action: empty chain, or only
        # initial-bind grants (which never authorize). Fail closed.
        if saw_initial_bind:
            return Verdict(VIOLATED, "initial_bind_authorizes_nothing", None)
        return Verdict(VIOLATED, "no_authority_chain", None)
    return Verdict(SATISFIED, "ok", None)
