"""Structural tests for verify_authority_chain_trace — the per-node trace
sibling of verify_authority_chain. Behavioral parity with the existing
aggregate is covered separately in tests/test_conformance.py; these tests
only check the new `chains` structure."""

from __future__ import annotations

import json
import pathlib

from sm_dat.verify import verify_authority_chain_trace

VEC = pathlib.Path(__file__).parent.parent / "vectors" / "dat" / "0.1"


def _load(name: str) -> dict:
    return json.loads((VEC / f"{name}.json").read_text())


def test_two_hop_chain_traces_leaf_to_root_with_depths():
    v = _load("25-subdelegation_valid_narrowing")
    grants = {g["grant_id"]: g for g in v["grants"]}

    trace = verify_authority_chain_trace(v["receipt"], grants)

    assert trace.aggregate.status == "SATISFIED"
    assert trace.aggregate.reason == "ok"
    assert len(trace.chains) == 1
    leaf_id = v["receipt"]["authority_chain"][0]
    nodes = trace.chains[0]
    assert [n.grant_id for n in nodes] == [
        leaf_id,
        grants[leaf_id]["delegation"]["parent_grant_id"],
    ]
    assert [n.depth for n in nodes] == [0, 1]
    assert all(n.verdict.status == "SATISFIED" for n in nodes)
    assert all(not n.is_initial_bind for n in nodes)


def test_missing_top_level_grant_still_produces_a_node():
    v = _load("25-subdelegation_valid_narrowing")
    grants = {g["grant_id"]: g for g in v["grants"]}
    receipt = dict(v["receipt"], authority_chain=["dat:does-not-exist"])

    trace = verify_authority_chain_trace(receipt, grants)

    assert trace.aggregate.status == "VIOLATED"
    assert trace.aggregate.reason == "grant_not_found"
    assert len(trace.chains) == 1
    assert len(trace.chains[0]) == 1
    assert trace.chains[0][0].grant_id == "dat:does-not-exist"
    assert trace.chains[0][0].verdict.reason == "grant_not_found"


def test_last_indeterminate_entry_wins_when_no_violation():
    """Matches the original verify_authority_chain's unconditional
    ``pending_ind = verdict`` — with two INDETERMINATE entries and no
    VIOLATED anywhere, the LAST one processed wins, not the first. Uses two
    existing single-grant vectors that share the same action/issuer but
    each independently produce a different INDETERMINATE reason."""
    v22 = _load("22-revocation_no_checker_indeterminate")  # -> revocation_unknown
    v23 = _load("23-predicate_unsupported_indeterminate")  # -> predicate_unsupported
    grants = {v22["grant"]["grant_id"]: v22["grant"], v23["grant"]["grant_id"]: v23["grant"]}
    receipt = {
        "issuer_did": v22["agent_did"],
        "issued_at": v22["issued_at"],
        "action": v22["action"],
        "authority_chain": [v22["grant"]["grant_id"], v23["grant"]["grant_id"]],
    }

    trace = verify_authority_chain_trace(receipt, grants)
    assert trace.aggregate.status == "INDETERMINATE"
    assert trace.aggregate.reason == "predicate_unsupported", "last entry (v23) should win"

    reversed_receipt = dict(receipt, authority_chain=list(reversed(receipt["authority_chain"])))
    reversed_trace = verify_authority_chain_trace(reversed_receipt, grants)
    assert reversed_trace.aggregate.reason == "revocation_unknown", "last entry (v22) should win"
