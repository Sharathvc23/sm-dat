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


@dataclass(frozen=True)
class GrantNode:
    """One grant's own individual verification result within a chain trace.

    ``depth`` is 0 for the grant named directly in ``authority_chain``,
    increasing toward the root along ``parent_grant_id``. For depth 0,
    ``verdict`` is the full ``verify_grant`` result (scope, temporal,
    revocation, predicate — everything). For depth > 0, ``verdict`` collapses
    the ancestor-only checks (signature, grantor/grantee continuity,
    attenuation) into one Verdict.
    """
    grant_id: str
    verdict: Verdict
    depth: int
    is_initial_bind: bool


@dataclass(frozen=True)
class ChainTrace:
    """Per-node trace alongside the same aggregate `verify_authority_chain`
    returns. `chains` holds one leaf-to-root list per `authority_chain`
    entry, in receipt order — unlike the aggregate-only function, every
    entry is walked and recorded even after an earlier entry has already
    failed, so the report reflects the whole receipt, not just however far
    a pass/fail short-circuit got."""
    aggregate: Verdict
    chains: list[list[GrantNode]]


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


def _walk_chain_entry(
    gid: str,
    grants: dict[str, dict[str, Any]],
) -> tuple[list[GrantNode], Verdict | None]:
    """Walk one authority_chain entry's ancestors leaf-to-root along
    ``parent_grant_id``, stopping at the first ancestor-level failure — the
    same bound ``verify_authority_chain`` always applied, just recorded
    instead of returned immediately. ``nodes`` excludes the leaf itself (the
    caller adds it after running ``verify_grant``). Returns
    ``(nodes, ancestor_failure)`` where ``ancestor_failure`` is ``None`` if
    every ancestor checked out.
    """
    grant = grants[gid]
    nodes: list[GrantNode] = []
    depth, cur = 0, grant
    max_depth = (grant.get("delegation") or {}).get("max_depth", 4)
    while (cur.get("delegation") or {}).get("parent_grant_id"):
        parent_id = cur["delegation"]["parent_grant_id"]
        parent = grants.get(parent_id)
        if parent is None:
            v = Verdict(VIOLATED, "grant_not_found", parent_id)
            nodes.append(GrantNode(parent_id, v, depth + 1, False))
            return nodes, v
        if not verify_grant_signature(parent):
            v = Verdict(VIOLATED, "bad_signature", parent_id, "ancestor grant")
            nodes.append(GrantNode(parent_id, v, depth + 1, False))
            return nodes, v
        if cur.get("grantor_did") != parent.get("grantee_did"):
            v = Verdict(
                VIOLATED, "chain_discontinuity", parent_id,
                f"child.grantor_did {cur.get('grantor_did')!r} != "
                f"parent.grantee_did {parent.get('grantee_did')!r}",
            )
            nodes.append(GrantNode(parent_id, v, depth + 1, False))
            return nodes, v
        att = check_attenuation(cur, parent)
        if not att.ok:
            nodes.append(GrantNode(parent_id, att, depth + 1, False))
            return nodes, att
        depth += 1
        if depth > max_depth:
            v = Verdict(VIOLATED, "depth_exceeded", gid, f"depth {depth} > {max_depth}")
            nodes.append(GrantNode(parent_id, v, depth, False))
            return nodes, v
        nodes.append(GrantNode(parent_id, att, depth, False))
        cur = parent
    return nodes, None


def _trace_chain_entry(
    gid: str,
    grants: dict[str, dict[str, Any]],
    receipt: dict[str, Any],
    *,
    ledger_context: LedgerContext | None,
    revocation_checker: Callable[[str, str], bool | None] | None,
    predicate_evaluator: Callable[[str, dict[str, Any], dict[str, Any]], bool] | None,
) -> tuple[list[GrantNode], Verdict | None]:
    """One authority_chain entry, leaf + full ancestor walk. Returns
    ``(nodes leaf-to-root, contributed)`` where ``contributed`` is this
    entry's Verdict toward the aggregate, or ``None`` for a neutral
    initial-bind entry (SPEC §3.0 — never authorizes, never blocks).

    Matches ``verify_authority_chain``'s original check order exactly:
    ancestors first, the leaf's own ``verify_grant`` last — if an ancestor
    fails, the leaf is never independently evaluated (its node records
    ``INDETERMINATE(not_evaluated)`` rather than guessing).
    """
    grant = grants.get(gid)
    if grant is None:
        return [], Verdict(VIOLATED, "grant_not_found", gid)
    if grant.get("initial_bind"):
        return [GrantNode(gid, Verdict(SATISFIED, "initial_bind_neutral", gid), 0, True)], None

    ancestor_nodes, ancestor_failure = _walk_chain_entry(gid, grants)
    if ancestor_failure is not None:
        leaf_node = GrantNode(
            gid, Verdict(INDETERMINATE, "not_evaluated", gid, "skipped: an ancestor failed first"),
            0, False,
        )
        return [leaf_node, *ancestor_nodes], ancestor_failure

    leaf_verdict = verify_grant(
        grant, receipt["action"], receipt["issued_at"],
        agent_did=receipt.get("issuer_did"),
        receipt_id=receipt.get("receipt_id") or "",
        ledger_context=ledger_context,
        revocation_checker=revocation_checker,
        predicate_evaluator=predicate_evaluator,
    )
    leaf_node = GrantNode(gid, leaf_verdict, 0, False)
    return [leaf_node, *ancestor_nodes], leaf_verdict


def verify_authority_chain_trace(
    receipt: dict[str, Any],
    grants: dict[str, dict[str, Any]],
    *,
    ledger_contexts: dict[str, LedgerContext] | None = None,
    revocation_checker: Callable[[str, str], bool | None] | None = None,
    predicate_evaluator: Callable[[str, dict[str, Any], dict[str, Any]], bool] | None = None,
) -> ChainTrace:
    """Same decision procedure as ``verify_authority_chain`` (SPEC §5.3), but
    walks every ``authority_chain`` entry instead of stopping at the first
    VIOLATED, so ``chains`` reflects the whole receipt. ``aggregate`` is
    unchanged — exactly the Verdict ``verify_authority_chain`` would return.

    Note: entries after the first violation are still fully evaluated
    (including calling ``revocation_checker``/``predicate_evaluator``/
    ``ledger_context``) for trace completeness — these callbacks are
    query-only per their existing contract, so this has no side effects
    beyond the extra call.
    """
    chain = receipt.get("authority_chain") or []
    ledger_contexts = ledger_contexts or {}
    chains: list[list[GrantNode]] = []

    first_violation: Verdict | None = None
    pending_ind: Verdict | None = None
    authorizing = 0
    saw_initial_bind = False

    for gid in chain:
        nodes, contributed = _trace_chain_entry(
            gid, grants, receipt,
            ledger_context=ledger_contexts.get(gid),
            revocation_checker=revocation_checker,
            predicate_evaluator=predicate_evaluator,
        )
        chains.append(nodes)

        if contributed is None:
            saw_initial_bind = True
            continue
        if contributed.status == VIOLATED:
            if first_violation is None:
                first_violation = contributed
        elif contributed.status == INDETERMINATE:
            if pending_ind is None:
                pending_ind = contributed
        else:
            authorizing += 1

    if first_violation is not None:
        aggregate = first_violation
    elif pending_ind is not None:
        aggregate = pending_ind
    elif authorizing == 0:
        aggregate = Verdict(
            VIOLATED,
            "initial_bind_authorizes_nothing" if saw_initial_bind else "no_authority_chain",
            None,
        )
    else:
        aggregate = Verdict(SATISFIED, "ok", None)

    return ChainTrace(aggregate=aggregate, chains=chains)


def verify_authority_chain(
    receipt: dict[str, Any],
    grants: dict[str, dict[str, Any]],
    *,
    ledger_contexts: dict[str, LedgerContext] | None = None,
    revocation_checker: Callable[[str, str], bool | None] | None = None,
    predicate_evaluator: Callable[[str, dict[str, Any], dict[str, Any]], bool] | None = None,
) -> Verdict:
    """Aggregate over every grant in ``receipt.authority_chain`` (SPEC §5.3).
    Thin wrapper — see ``verify_authority_chain_trace`` for the per-node
    trace this is built on."""
    return verify_authority_chain_trace(
        receipt, grants,
        ledger_contexts=ledger_contexts,
        revocation_checker=revocation_checker,
        predicate_evaluator=predicate_evaluator,
    ).aggregate
