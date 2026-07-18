"""Replay the dat/0.1 conformance corpus against the reference verifier.

Each JSON vector pins an expected (status, reason). This is the contract any
conformant DAT implementation must reproduce — the negative and INDETERMINATE
cases especially.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from sm_dat import LedgerContext, StaticRevocationList, verify_authority_chain, verify_grant
from sm_dat.verify import verify_authority_chain_trace

VEC = pathlib.Path(__file__).parent.parent / "vectors" / "dat" / "0.1"
FILES = sorted(VEC.glob("*.json"))


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_vector(path):
    v = json.loads(path.read_text())
    want_status, want_reason = v["expect"]

    if v["kind"] == "grant":
        ledger = LedgerContext.from_receipts(v["ledger"], v["grant"]["grant_id"]) if v.get("ledger") else None
        rev = None
        if v.get("revocation"):
            r = v["revocation"]
            rev = StaticRevocationList(r["entries"], fetched_at=r["fetched_at"], max_age_seconds=r["max_age"])
        verdict = verify_grant(v["grant"], v["action"], v["issued_at"],
                               agent_did=v.get("agent_did"), receipt_id=v.get("receipt_id", ""),
                               ledger_context=ledger, revocation_checker=rev)
    elif v["kind"] == "chain":
        grants = {g["grant_id"]: g for g in v["grants"]}
        ledgers = {gid: LedgerContext.from_receipts(v.get("ledger", []), gid) for gid in grants} if v.get("ledger") else None
        verdict = verify_authority_chain(v["receipt"], grants, ledger_contexts=ledgers)
    else:
        pytest.fail(f"unknown vector kind {v['kind']!r}")

    assert verdict.status == want_status, f"{path.stem}: status {verdict.status} != {want_status} ({verdict.detail})"
    assert verdict.reason == want_reason, f"{path.stem}: reason {verdict.reason!r} != {want_reason!r}"


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_trace_aggregate_matches_verify_authority_chain(path):
    """verify_authority_chain is now a wrapper around
    verify_authority_chain_trace — for every existing conformance vector,
    the two must return identical aggregates. Proves the refactor changes
    nothing already shipped and tested."""
    v = json.loads(path.read_text())
    if v["kind"] != "chain":
        pytest.skip("trace function only applies to chain-kind vectors")

    grants = {g["grant_id"]: g for g in v["grants"]}
    ledgers = {gid: LedgerContext.from_receipts(v.get("ledger", []), gid) for gid in grants} if v.get("ledger") else None

    direct = verify_authority_chain(v["receipt"], grants, ledger_contexts=ledgers)
    traced = verify_authority_chain_trace(v["receipt"], grants, ledger_contexts=ledgers).aggregate

    assert traced == direct, f"{path.stem}: trace aggregate {traced} != direct {direct}"


def test_corpus_nonempty():
    assert FILES, "no conformance vectors found — run vectors/_generate.py"
