"""The verification decision procedure (SPEC §5–§6).

Three-valued by design: SATISFIED / VIOLATED / INDETERMINATE. The library never
collapses INDETERMINATE into pass or fail — that policy belongs to the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Collection

from .grant import verify_grant_signature
from .ledger import LedgerContext

SATISFIED = "SATISFIED"
VIOLATED = "VIOLATED"
INDETERMINATE = "INDETERMINATE"

_REQUIRED = ("version", "grant_id", "grantor_did", "grantee_did", "issued_at",
             "not_before", "not_after", "human_summary", "scope", "signature")

DEFAULT_MAX_DEPTH = 4

RevocationChecker = Callable[[str, str], "bool | None"]
PredicateEvaluator = Callable[[str, dict[str, Any], dict[str, Any]], bool]


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
    the ancestor checks (structure, signature, grantor/grantee continuity,
    attenuation, validity window, revocation) into one Verdict.
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


def parse_rfc3339(ts: Any) -> datetime | None:
    """Parse an RFC 3339 timestamp to an aware UTC datetime, or ``None`` when
    the value is not a string, does not parse, or carries no UTC offset (a
    naive timestamp would be read in the verifier's local zone — a verdict
    that depends on where the verifier runs is not a verdict).

    Never raises: a malformed timestamp is a *verdict* (``VIOLATED(malformed)``),
    not an exception escaping the decision procedure (SPEC §5.1 step 1).
    """
    if not isinstance(ts, str) or not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        return None
    return d.astimezone(timezone.utc)


def _structure(grant: Any) -> str | None:
    """SPEC §5.1 step 1 — required fields present and well-typed. Returns the
    ``malformed`` detail, or ``None`` when the envelope is structurally sound.
    Shared by the leaf check in ``verify_grant`` and the ancestor checks in
    the chain walk, so an ancestor is held to the same envelope rules as the
    grant presented directly."""
    if not isinstance(grant, dict):
        return "grant is not an object"
    for f in _REQUIRED:
        if f not in grant:
            return f"missing {f!r}"
    if grant["version"] != "dat/0.1":
        return f"unexpected version {grant['version']!r}"
    for f in ("grant_id", "grantor_did", "grantee_did", "signature"):
        if not isinstance(grant[f], str) or not grant[f]:
            return f"{f} must be a non-empty string"
    if not isinstance(grant["human_summary"], str):
        return "human_summary must be a string"
    if len(grant["human_summary"]) > 280:
        return "human_summary exceeds 280 code points"
    scope = grant["scope"]
    if not isinstance(scope, dict) or not isinstance(scope.get("action_categories"), list):
        return "scope.action_categories must be a list"
    for f in ("issued_at", "not_before", "not_after"):
        if parse_rfc3339(grant[f]) is None:
            return f"{f} is not an RFC 3339 timestamp: {grant[f]!r}"
    delegation = grant.get("delegation")
    if delegation is not None:
        if not isinstance(delegation, dict):
            return "delegation must be an object"
        parent = delegation.get("parent_grant_id")
        if parent is not None and (not isinstance(parent, str) or not parent):
            return "delegation.parent_grant_id must be a non-empty string or null"
        md = delegation.get("max_depth", DEFAULT_MAX_DEPTH)
        if isinstance(md, bool) or not isinstance(md, int) or md < 0:
            return "delegation.max_depth must be a non-negative integer"
    return None


def _is_root(grant: dict[str, Any]) -> bool:
    return not (grant.get("delegation") or {}).get("parent_grant_id")


def _max_depth(grant: dict[str, Any]) -> int:
    return (grant.get("delegation") or {}).get("max_depth", DEFAULT_MAX_DEPTH)


def verify_grant(
    grant: dict[str, Any],
    action: dict[str, Any],
    issued_at: str,
    *,
    agent_did: str | None,
    receipt_id: str = "",
    ledger_context: LedgerContext | None = None,
    revocation_checker: RevocationChecker | None = None,
    predicate_evaluator: PredicateEvaluator | None = None,
    require_revocation_source: bool = False,
    trusted_grantors: Collection[str] | None = None,
) -> Verdict:
    """Decide whether one DAT authorizes one action at ``issued_at`` (SPEC §5.1).

    ``agent_did`` is the acting agent's DID (the receipt's ``issuer_did``) and
    is required: a grant is a statement *about a grantee*, and a verdict that
    never compared the actor to the grantee would vouch for nobody. It is
    keyword-only and has no default (0.3.0); a caller that genuinely does not
    know the actor may pass ``None`` and receives ``INDETERMINATE(grantee_unbound)``
    — never a silent pass.

    ``revocation_checker(grant_id, issued_at)`` returns True if revoked, False if
    known-live, or None if it cannot tell (→ INDETERMINATE). The revocation gate
    runs only for grants that *declare* a revocation source (SPEC §5.1 step 5);
    ``require_revocation_source=True`` lets a relying party refuse grants that
    declare none (``VIOLATED(no_revocation_source)``) instead of accepting them
    as irrevocable-by-omission.

    ``trusted_grantors``, when supplied, is the set of DIDs this verifier
    accepts as the *root* of authority (SPEC §5.4 O1): a root grant whose
    ``grantor_did`` is not in it is ``VIOLATED(untrusted_grantor)``. For a
    child grant this function cannot see the root, so it answers
    ``INDETERMINATE(root_grantor_unresolved)`` — the chain walk
    (``verify_authority_chain``) resolves the root and applies the set there.
    """
    gid = grant.get("grant_id") if isinstance(grant, dict) else None

    def v(reason: str, detail: str = "") -> Verdict:
        return Verdict(VIOLATED, reason, gid, detail)

    def ind(reason: str, detail: str = "") -> Verdict:
        return Verdict(INDETERMINATE, reason, gid, detail)

    # 1. structure — the grant's envelope, and the action timestamp the whole
    # decision is anchored to. A timestamp that does not parse is a verdict,
    # not an exception.
    bad = _structure(grant)
    if bad is not None:
        return v("malformed", bad)
    t = parse_rfc3339(issued_at)
    if t is None:
        return v("malformed", f"issued_at is not an RFC 3339 timestamp: {issued_at!r}")

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

    # 2a. grantor trust (O1). A valid signature proves key possession, not that
    # the key is the principal's. When the relying party names the grantors it
    # trusts, the root of authority must be one of them.
    if trusted_grantors is not None:
        if not _is_root(grant):
            return ind("root_grantor_unresolved",
                       "child grant: the root grantor is established by the chain walk")
        if grant["grantor_did"] not in trusted_grantors:
            return v("untrusted_grantor", grant["grantor_did"])

    # 3. grantee
    if not isinstance(agent_did, str) or not agent_did:
        return ind("grantee_unbound", "no acting agent DID supplied to compare against grantee_did")
    if agent_did != grant["grantee_did"]:
        return v("grantee_mismatch", f"{agent_did} != {grant['grantee_did']}")

    # 4. temporal (timestamps already validated in step 1)
    if t < parse_rfc3339(grant["not_before"]):  # type: ignore[operator]
        return v("not_yet_valid")
    if t > parse_rfc3339(grant["not_after"]):  # type: ignore[operator]
        return v("expired")

    # 5. revocation
    if grant.get("revocation") is None:
        if require_revocation_source:
            return v("no_revocation_source", "grant declares no revocation source")
    else:
        if revocation_checker is None:
            return ind("revocation_unknown", "no revocation_checker supplied")
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
    """A child grant MUST be at least as restrictive as its parent on every
    dimension (SPEC §6): categories, per-action cap, currency, counterparty
    allowlist, jurisdictions, per-period cap, predicate, validity window
    (both ends) and ``max_depth``. Any widening ⇒ ``attenuation_breach``.
    A structurally unreadable grant ⇒ ``malformed`` — never an exception."""
    cid = child.get("grant_id")

    def breach(d: str) -> Verdict:
        return Verdict(VIOLATED, "attenuation_breach", cid, d)

    def malformed(d: str) -> Verdict:
        return Verdict(VIOLATED, "malformed", cid, d)

    cs, ps = child.get("scope"), parent.get("scope")
    if not isinstance(cs, dict) or not isinstance(ps, dict):
        return malformed("scope must be an object")
    ccats, pcats = cs.get("action_categories"), ps.get("action_categories")
    if not isinstance(ccats, list) or not isinstance(pcats, list):
        return malformed("scope.action_categories must be a list")
    if not set(ccats) <= set(pcats):
        return breach("categories widen")

    csl, psl = cs.get("stateless") or {}, ps.get("stateless") or {}
    if "amount_cents_per_action_max" in psl:
        if csl.get("amount_cents_per_action_max", float("inf")) > psl["amount_cents_per_action_max"]:
            return breach("per-action cap widens")
    if "amount_currency" in psl:
        # A parent's cap is denominated in one currency; a child that drops or
        # changes it re-denominates (or un-denominates) the bound.
        if csl.get("amount_currency") != psl["amount_currency"]:
            return breach("amount_currency differs from parent")
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

    # A parent's predicate is a condition on every action under it; a child
    # that drops or rewrites it has escaped the condition. 0.1 has no predicate
    # algebra to decide "narrower", so the child MUST carry it verbatim.
    if ps.get("predicate") is not None and cs.get("predicate") != ps["predicate"]:
        return breach("predicate dropped or changed")

    c_nb, c_na = parse_rfc3339(child.get("not_before")), parse_rfc3339(child.get("not_after"))
    p_nb, p_na = parse_rfc3339(parent.get("not_before")), parse_rfc3339(parent.get("not_after"))
    if c_nb is None or c_na is None:
        return malformed("child not_before/not_after is not an RFC 3339 timestamp")
    if p_nb is None or p_na is None:
        return malformed("parent not_before/not_after is not an RFC 3339 timestamp")
    if c_na > p_na:
        return breach("not_after extends past parent")
    if c_nb < p_nb:
        return breach("not_before precedes parent")

    cd, pd = (child.get("delegation") or {}), (parent.get("delegation") or {})
    if not isinstance(cd, dict) or not isinstance(pd, dict):
        return malformed("delegation must be an object")
    c_md, p_md = cd.get("max_depth", DEFAULT_MAX_DEPTH), pd.get("max_depth", DEFAULT_MAX_DEPTH)
    if not isinstance(c_md, int) or not isinstance(p_md, int):
        return malformed("delegation.max_depth must be an integer")
    if c_md > p_md:
        return breach(f"max_depth widens ({c_md} > {p_md})")

    return Verdict(SATISFIED, "ok", cid)


def _walk_chain_entry(
    gid: str,
    grants: dict[str, dict[str, Any]],
    issued_at: str,
    *,
    revocation_checker: RevocationChecker | None,
    require_revocation_source: bool,
    trusted_grantors: Collection[str] | None,
) -> tuple[list[GrantNode], Verdict | None]:
    """Walk one authority_chain entry's ancestors leaf-to-root along
    ``parent_grant_id`` (SPEC §6), stopping at the first non-SATISFIED
    ancestor-level result. ``nodes`` excludes the leaf itself (the caller
    adds it after running ``verify_grant``). Returns ``(nodes, stop)`` where
    ``stop`` is ``None`` if every ancestor checked out. A ``stop`` whose
    ``grant_id`` is the leaf's (``depth_exceeded``, a malformed leaf, an
    untrusted root grantor when the leaf *is* the root) belongs to the leaf
    node; the caller places it there.

    Each ancestor is held to the checks a directly-presented grant gets that
    do not depend on the action's scope: structure, self-grant, signature,
    continuity with its child, attenuation of its child, its own validity
    window at the action's ``issued_at``, and its own revocation. A revoked
    or not-yet-valid parent cannot lend authority to a child, however well
    the child itself narrows.

    ``max_depth`` is taken from the ROOT grant — the one the principal
    signed — never from the leaf, which the delegating agent signs and could
    set arbitrarily. Attenuation additionally pins every child's
    ``max_depth`` to ≤ its parent's, so the root's bound is the chain's.
    """
    grant = grants[gid]
    nodes: list[GrantNode] = []

    bad = _structure(grant)
    if bad is not None:
        return nodes, Verdict(VIOLATED, "malformed", gid, bad)
    t = parse_rfc3339(issued_at)
    if t is None:
        return nodes, Verdict(VIOLATED, "malformed", gid,
                              f"issued_at is not an RFC 3339 timestamp: {issued_at!r}")

    seen = {gid}
    depth, cur = 0, grant
    while not _is_root(cur):
        parent_id = cur["delegation"]["parent_grant_id"]
        depth += 1

        def fail(status: str, reason: str, detail: str = "") -> tuple[list[GrantNode], Verdict]:
            v = Verdict(status, reason, parent_id, detail)
            nodes.append(GrantNode(parent_id, v, depth, False))
            return nodes, v

        if parent_id in seen:
            return fail(VIOLATED, "chain_cycle", f"{parent_id!r} already appears in this chain")
        seen.add(parent_id)
        parent = grants.get(parent_id)
        if parent is None:
            return fail(VIOLATED, "grant_not_found")
        bad = _structure(parent)
        if bad is not None:
            return fail(VIOLATED, "malformed", f"ancestor grant: {bad}")
        if parent["grantor_did"] == parent["grantee_did"]:
            return fail(VIOLATED, "self_grant", "ancestor grant: grantor_did == grantee_did")
        if not verify_grant_signature(parent):
            return fail(VIOLATED, "bad_signature", "ancestor grant")
        if cur["grantor_did"] != parent["grantee_did"]:
            return fail(VIOLATED, "chain_discontinuity",
                        f"child.grantor_did {cur['grantor_did']!r} != "
                        f"parent.grantee_did {parent['grantee_did']!r}")
        att = check_attenuation(cur, parent)
        if not att.ok:
            nodes.append(GrantNode(parent_id, att, depth, False))
            return nodes, att
        # The ancestor's own validity window, at the action's time. The leaf's
        # window is checked by verify_grant; an ancestor outside its window
        # had no authority to delegate at that moment.
        if t < parse_rfc3339(parent["not_before"]):  # type: ignore[operator]
            return fail(VIOLATED, "ancestor_not_yet_valid", f"ancestor not_before {parent['not_before']}")
        if t > parse_rfc3339(parent["not_after"]):  # type: ignore[operator]
            return fail(VIOLATED, "ancestor_expired", f"ancestor not_after {parent['not_after']}")
        # The ancestor's own revocation — same gate as verify_grant step 5.
        if parent.get("revocation") is None:
            if require_revocation_source:
                return fail(VIOLATED, "no_revocation_source", "ancestor grant declares no revocation source")
        else:
            if revocation_checker is None:
                return fail(INDETERMINATE, "revocation_unknown",
                            "ancestor declares a revocation source; no revocation_checker supplied")
            state = revocation_checker(parent_id, issued_at)
            if state is None:
                return fail(INDETERMINATE, "revocation_unknown", "ancestor: checker could not resolve")
            if state:
                return fail(VIOLATED, "ancestor_revoked")

        nodes.append(GrantNode(parent_id, Verdict(SATISFIED, "ok", parent_id), depth, False))
        cur = parent

    root = cur
    max_depth = _max_depth(root)
    if depth > max_depth:
        return nodes, Verdict(VIOLATED, "depth_exceeded", gid, f"depth {depth} > root max_depth {max_depth}")
    if trusted_grantors is not None and root["grantor_did"] not in trusted_grantors:
        v = Verdict(VIOLATED, "untrusted_grantor", root["grant_id"], root["grantor_did"])
        if nodes:  # the root is an ancestor: its node carries the verdict
            nodes[-1] = GrantNode(root["grant_id"], v, depth, False)
        return nodes, v
    return nodes, None


def _trace_chain_entry(
    gid: str,
    grants: dict[str, dict[str, Any]],
    receipt: dict[str, Any],
    *,
    ledger_context: LedgerContext | None,
    revocation_checker: RevocationChecker | None,
    predicate_evaluator: PredicateEvaluator | None,
    require_revocation_source: bool,
    trusted_grantors: Collection[str] | None,
) -> tuple[list[GrantNode], Verdict | None]:
    """One authority_chain entry, leaf + full ancestor walk. Returns
    ``(nodes leaf-to-root, contributed)`` where ``contributed`` is this
    entry's Verdict toward the aggregate, or ``None`` for a neutral
    initial-bind entry (SPEC §3.0 — never authorizes, never blocks).

    Ancestors first, the leaf's own ``verify_grant`` last — if an ancestor
    fails, the leaf is never independently evaluated (its node records
    ``INDETERMINATE(not_evaluated)`` rather than guessing).
    """
    grant = grants.get(gid)
    if grant is None:
        v = Verdict(VIOLATED, "grant_not_found", gid)
        return [GrantNode(gid, v, 0, False)], v
    if isinstance(grant, dict) and grant.get("initial_bind"):
        return [GrantNode(gid, Verdict(SATISFIED, "initial_bind_neutral", gid), 0, True)], None

    issued_at = receipt.get("issued_at")
    ancestor_nodes, stop = _walk_chain_entry(
        gid, grants, issued_at,
        revocation_checker=revocation_checker,
        require_revocation_source=require_revocation_source,
        trusted_grantors=trusted_grantors,
    )
    if stop is not None:
        if stop.grant_id == gid:
            leaf_verdict = stop
        else:
            leaf_verdict = Verdict(INDETERMINATE, "not_evaluated", gid, "skipped: an ancestor failed first")
        return [GrantNode(gid, leaf_verdict, 0, False), *ancestor_nodes], stop

    # The walk has already bound the root grantor against ``trusted_grantors``
    # (the leaf's grantor is an agent for any child grant), so the leaf is
    # verified without the set.
    leaf_verdict = verify_grant(
        grant, receipt["action"], issued_at,
        agent_did=receipt.get("issuer_did"),
        receipt_id=receipt.get("receipt_id") or "",
        ledger_context=ledger_context,
        revocation_checker=revocation_checker,
        predicate_evaluator=predicate_evaluator,
        require_revocation_source=require_revocation_source,
    )
    return [GrantNode(gid, leaf_verdict, 0, False), *ancestor_nodes], leaf_verdict


def verify_authority_chain_trace(
    receipt: dict[str, Any],
    grants: dict[str, dict[str, Any]],
    *,
    ledger_contexts: dict[str, LedgerContext] | None = None,
    revocation_checker: RevocationChecker | None = None,
    predicate_evaluator: PredicateEvaluator | None = None,
    require_revocation_source: bool = False,
    trusted_grantors: Collection[str] | None = None,
) -> ChainTrace:
    """Same decision procedure as ``verify_authority_chain`` (SPEC §5.3), but
    walks every ``authority_chain`` entry instead of stopping at the first
    VIOLATED, so ``chains`` reflects the whole receipt. ``aggregate`` is
    unchanged — exactly the Verdict ``verify_authority_chain`` would return,
    for every well-formed input the two entry points share.

    Note: entries after the first violation are still fully evaluated
    (including calling ``revocation_checker``/``predicate_evaluator``/
    ``ledger_context``) for trace completeness — these callbacks are
    query-only per their existing contract, so this has no side effects
    beyond the extra call.

    Never raises, even on a malformed grant. Structural defects the walk can
    name (a non-object ``delegation``, a non-RFC 3339 timestamp, a missing
    field) are ``VIOLATED(malformed)`` with the defect in ``detail``. Anything
    that still trips an internal error mid-walk is caught per-entry and
    turned into ``VIOLATED(malformed_grant)`` rather than propagating — the
    one deliberate catch-all in this module, kept because walking every
    entry (for trace completeness) reaches grants a short-circuit would skip.
    """
    raw_chain = receipt.get("authority_chain")
    chain = raw_chain if isinstance(raw_chain, list) else []
    ledger_contexts = ledger_contexts or {}
    chains: list[list[GrantNode]] = []

    first_violation: Verdict | None = None
    pending_ind: Verdict | None = None
    authorizing = 0
    saw_initial_bind = False

    for gid in chain:
        try:
            nodes, contributed = _trace_chain_entry(
                gid, grants, receipt,
                ledger_context=ledger_contexts.get(gid),
                revocation_checker=revocation_checker,
                predicate_evaluator=predicate_evaluator,
                require_revocation_source=require_revocation_source,
                trusted_grantors=trusted_grantors,
            )
        except Exception as exc:  # noqa: BLE001 — see docstring: deliberate
            malformed = Verdict(VIOLATED, "malformed_grant", gid, str(exc))
            nodes, contributed = [GrantNode(gid, malformed, 0, False)], malformed
        chains.append(nodes)

        if contributed is None:
            saw_initial_bind = True
            continue
        if contributed.status == VIOLATED:
            if first_violation is None:
                first_violation = contributed
        elif contributed.status == INDETERMINATE:
            # Unconditional overwrite, matching the original function: with
            # no VIOLATED anywhere, the LAST indeterminate entry processed
            # wins, not the first.
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
    revocation_checker: RevocationChecker | None = None,
    predicate_evaluator: PredicateEvaluator | None = None,
    require_revocation_source: bool = False,
    trusted_grantors: Collection[str] | None = None,
) -> Verdict:
    """Aggregate over every grant in ``receipt.authority_chain`` (SPEC §5.3).
    Thin wrapper — see ``verify_authority_chain_trace`` for the per-node
    trace this is built on."""
    return verify_authority_chain_trace(
        receipt, grants,
        ledger_contexts=ledger_contexts,
        revocation_checker=revocation_checker,
        predicate_evaluator=predicate_evaluator,
        require_revocation_source=require_revocation_source,
        trusted_grantors=trusted_grantors,
    ).aggregate
