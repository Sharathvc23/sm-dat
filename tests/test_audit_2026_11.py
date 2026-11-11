"""Direct tests for the 0.3.0 audit fixes (audit 2026-11). The conformance
corpus pins each verdict as a vector; these tests pin the *shape* of the fixes
— the parts a vector cannot express (a raised exception, a trace node, a
required argument, the order of checks)."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from sm_arp import build_action

from sm_dat import (
    Identity, StaticRevocationList, build_grant, check_attenuation, parse_rfc3339, sign_grant,
    verify_authority_chain, verify_authority_chain_trace, verify_grant,
)

P = Identity.from_seed(b"\x01" * 32)   # principal
A = Identity.from_seed(b"\x02" * 32)   # agent
A2 = Identity.from_seed(b"\x03" * 32)  # sub-agent
A3 = Identity.from_seed(b"\x04" * 32)  # sub-sub-agent
WHEN = "2026-04-10T19:00:00Z"
NB, NA = "2026-04-01T00:00:00Z", "2026-06-30T23:59:59Z"
AMC = {"amount_currency": "USD", "amount_cents_per_action_max": 5000,
       "counterparty_allowlist": ["domain:amctheatres.com"]}


def root(**over: Any) -> dict[str, Any]:
    kw: dict[str, Any] = dict(grantee_did=A.did, action_categories=["purchase"], not_before=NB,
                              not_after=NA, human_summary="root", stateless=dict(AMC))
    kw.update(over)
    return sign_grant(P, build_grant(**kw))


def child(parent: dict[str, Any], grantor: Identity = A, grantee: Identity = A2, **over: Any) -> dict[str, Any]:
    kw: dict[str, Any] = dict(grantee_did=grantee.did, action_categories=["purchase"], not_before=NB,
                              not_after=NA, human_summary="child", parent_grant_id=parent["grant_id"],
                              stateless={**AMC, "amount_cents_per_action_max": 3000})
    kw.update(over)
    return sign_grant(grantor, build_grant(**kw))


def buy(cents: int = 2500) -> dict[str, Any]:
    return build_action(category="purchase", human_summary="tickets", amount_cents=cents,
                        currency="USD", counterparty_label="domain:amctheatres.com")


def receipt(leaf: dict[str, Any], issuer: Identity = A2, issued_at: str = WHEN) -> dict[str, Any]:
    return {"issuer_did": issuer.did, "issued_at": issued_at, "receipt_id": "rcpt-1",
            "authority_chain": [leaf["grant_id"]], "action": buy()}


def grants(*gs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {g["grant_id"]: g for g in gs}


# --- #1 ancestor revocation and validity window ----------------------------

def test_revoked_parent_cannot_authorize_its_child():
    parent = root(revocation={"revocation_lookup_uri": "https://p.example/rev"})
    kid = child(parent)
    revoked = StaticRevocationList([{"grant_id": parent["grant_id"], "revoked_at": "2026-04-09T00:00:00Z"}],
                                   fetched_at=WHEN)
    v = verify_authority_chain(receipt(kid), grants(parent, kid), revocation_checker=revoked)
    assert (v.status, v.reason, v.grant_id) == ("VIOLATED", "ancestor_revoked", parent["grant_id"])


def test_parent_declaring_revocation_without_checker_is_indeterminate_not_a_pass():
    parent = root(revocation={"revocation_lookup_uri": "https://p.example/rev"})
    kid = child(parent)
    trace = verify_authority_chain_trace(receipt(kid), grants(parent, kid))
    assert (trace.aggregate.status, trace.aggregate.reason) == ("INDETERMINATE", "revocation_unknown")
    leaf, anc = trace.chains[0]
    assert anc.verdict.status == "INDETERMINATE" and anc.depth == 1
    assert leaf.verdict.reason == "not_evaluated"


def test_action_before_parents_window_is_ancestor_not_yet_valid():
    parent = root(not_before="2026-05-01T00:00:00Z")
    kid = child(parent, not_before="2026-05-01T00:00:00Z")
    v = verify_authority_chain(receipt(kid), grants(parent, kid))
    assert (v.status, v.reason) == ("VIOLATED", "ancestor_not_yet_valid")


def test_action_after_parents_window_is_ancestor_expired():
    parent = root(not_after="2026-04-05T00:00:00Z")
    kid = child(parent, not_after="2026-04-05T00:00:00Z")
    v = verify_authority_chain(receipt(kid), grants(parent, kid))
    assert (v.status, v.reason) == ("VIOLATED", "ancestor_expired")


# --- #2 depth is root-bound ----------------------------------------------------

def test_depth_bound_comes_from_the_root_grant():
    r = root(max_depth=1)
    c = child(r, max_depth=1)
    gc = child(c, grantor=A2, grantee=A3, max_depth=1,
               stateless={**AMC, "amount_cents_per_action_max": 2000})
    trace = verify_authority_chain_trace(receipt(gc, issuer=A3), grants(r, c, gc))
    assert (trace.aggregate.status, trace.aggregate.reason) == ("VIOLATED", "depth_exceeded")
    assert "root max_depth 1" in trace.aggregate.detail
    # The verdict is the leaf's: it is the grant that is too deep.
    leaf = trace.chains[0][0]
    assert leaf.grant_id == gc["grant_id"] and leaf.verdict.reason == "depth_exceeded"
    # Both ancestors checked out individually.
    assert [n.verdict.status for n in trace.chains[0][1:]] == ["SATISFIED", "SATISFIED"]


def test_leaf_cannot_raise_its_own_depth_bound():
    r = root()  # default max_depth 4
    c = child(r, max_depth=99)
    v = verify_authority_chain(receipt(c), grants(r, c))
    assert (v.status, v.reason) == ("VIOLATED", "attenuation_breach") and "max_depth" in v.detail


def test_parent_grant_id_cycle_terminates_with_a_verdict():
    x = child({"grant_id": "dat:cycle:y"}, grantor=A, grantee=A2, grant_id="dat:cycle:x")
    y = child({"grant_id": "dat:cycle:x"}, grantor=A2, grantee=A, grant_id="dat:cycle:y")
    v = verify_authority_chain(receipt(x), grants(x, y))
    assert (v.status, v.reason) == ("VIOLATED", "chain_cycle")


# --- #3 attenuation covers every dimension ------------------------------------

def test_attenuation_rejects_each_newly_covered_widening():
    parent = root(predicate="action.amount.cents < 4000")
    ok = child(parent, predicate="action.amount.cents < 4000")
    assert check_attenuation(ok, parent).ok

    cases = {
        "not_before precedes parent": child(parent, predicate="action.amount.cents < 4000",
                                            not_before="2026-03-01T00:00:00Z"),
        "predicate dropped or changed": child(parent),
        "amount_currency differs from parent": child(parent, predicate="action.amount.cents < 4000",
                                                     stateless={**AMC, "amount_currency": "EUR",
                                                               "amount_cents_per_action_max": 3000}),
        "max_depth widens (99 > 4)": child(parent, predicate="action.amount.cents < 4000", max_depth=99),
    }
    for detail, kid in cases.items():
        v = check_attenuation(kid, parent)
        assert (v.status, v.reason, v.detail) == ("VIOLATED", "attenuation_breach", detail)


def test_attenuation_on_unreadable_timestamps_is_a_verdict():
    parent = root()
    kid = copy.deepcopy(child(parent))
    kid["not_before"] = "whenever"
    v = check_attenuation(kid, parent)
    assert (v.status, v.reason) == ("VIOLATED", "malformed")


# --- #4 malformed timestamps are verdicts, not exceptions ---------------------

def test_malformed_action_issued_at_is_a_verdict():
    v = verify_grant(root(), buy(), "not-a-time", agent_did=A.did)
    assert (v.status, v.reason) == ("VIOLATED", "malformed") and "issued_at" in v.detail


@pytest.mark.parametrize("field,value", [
    ("not_before", "2026-04-01"),           # date only
    ("not_after", "2026-06-30T23:59:59"),   # naive: no UTC offset
    ("issued_at", 1775000000),              # not a string
])
def test_malformed_grant_timestamp_is_a_verdict(field, value):
    g = copy.deepcopy(root())
    g[field] = value
    v = verify_grant(g, buy(), WHEN, agent_did=A.did)
    assert (v.status, v.reason) == ("VIOLATED", "malformed") and field in v.detail


def test_parse_rfc3339_requires_an_offset_and_never_raises():
    assert parse_rfc3339("2026-04-10T19:00:00Z") is not None
    assert parse_rfc3339("2026-04-10T21:00:00+02:00") == parse_rfc3339("2026-04-10T19:00:00Z")
    assert parse_rfc3339("2026-04-10T19:00:00") is None
    assert parse_rfc3339("") is None and parse_rfc3339(None) is None and parse_rfc3339(42) is None


def test_build_grant_rejects_malformed_inputs_at_construction():
    with pytest.raises(ValueError):
        build_grant(grantee_did=A.did, action_categories=["purchase"], not_after="soon", human_summary="x")
    with pytest.raises(ValueError):
        build_grant(grantee_did=A.did, action_categories=["purchase"], not_after=NA, human_summary="x",
                    max_depth=-1)


# --- #5 agent_did required; require_revocation_source -------------------------

def test_agent_did_is_a_required_keyword():
    with pytest.raises(TypeError):
        verify_grant(root(), buy(), WHEN)  # type: ignore[call-arg]


def test_agent_did_none_is_indeterminate_grantee_unbound():
    v = verify_grant(root(), buy(), WHEN, agent_did=None)
    assert (v.status, v.reason) == ("INDETERMINATE", "grantee_unbound")


def test_require_revocation_source_refuses_irrevocable_by_omission():
    g = root()
    assert verify_grant(g, buy(), WHEN, agent_did=A.did).ok
    v = verify_grant(g, buy(), WHEN, agent_did=A.did, require_revocation_source=True)
    assert (v.status, v.reason) == ("VIOLATED", "no_revocation_source")


def test_require_revocation_source_reaches_ancestors():
    parent = root()
    kid = child(parent, revocation={"revocation_lookup_uri": "https://a.example/rev"})
    live = StaticRevocationList([], fetched_at=WHEN)
    assert verify_authority_chain(receipt(kid), grants(parent, kid), revocation_checker=live).ok
    v = verify_authority_chain(receipt(kid), grants(parent, kid), revocation_checker=live,
                               require_revocation_source=True)
    assert (v.status, v.reason, v.grant_id) == ("VIOLATED", "no_revocation_source", parent["grant_id"])


# --- #6 trusted_grantors binds the ROOT grantor -------------------------------

def test_trusted_grantors_binds_root_not_leaf_grantor():
    parent = root()
    kid = child(parent)  # signed by A, the agent
    assert verify_authority_chain(receipt(kid), grants(parent, kid), trusted_grantors={P.did}).ok
    v = verify_authority_chain(receipt(kid), grants(parent, kid), trusted_grantors={A.did})
    assert (v.status, v.reason, v.grant_id) == ("VIOLATED", "untrusted_grantor", parent["grant_id"])


def test_verify_grant_alone_defers_a_childs_root_binding_to_the_chain():
    kid = child(root())
    v = verify_grant(kid, buy(), WHEN, agent_did=A2.did, trusted_grantors={P.did})
    assert (v.status, v.reason) == ("INDETERMINATE", "root_grantor_unresolved")


def test_empty_trusted_set_trusts_nobody():
    v = verify_grant(root(), buy(), WHEN, agent_did=A.did, trusted_grantors=set())
    assert (v.status, v.reason) == ("VIOLATED", "untrusted_grantor")
