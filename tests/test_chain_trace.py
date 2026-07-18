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
