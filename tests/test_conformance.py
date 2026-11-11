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


def _revocation(v):
    if not v.get("revocation"):
        return None
    r = v["revocation"]
    return StaticRevocationList(r["entries"], fetched_at=r["fetched_at"], max_age_seconds=r["max_age"])


def _policy(v):
    """The relying-party switches a vector may set (0.3.0)."""
    return {
        "require_revocation_source": bool(v.get("require_revocation_source", False)),
        "trusted_grantors": set(v["trusted_grantors"]) if "trusted_grantors" in v else None,
    }


def _chain_inputs(v):
    """A vector's receipt / grants / ledgers, whatever its kind. A ``grant``
    vector is lifted into a one-entry authority_chain over the same action,
    agent and timestamp — the shape ``verify_authority_chain`` sees when a
    receipt cites exactly that grant."""
    if v["kind"] == "chain":
        grants = {g["grant_id"]: g for g in v["grants"]}
        ledgers = ({gid: LedgerContext.from_receipts(v.get("ledger", []), gid) for gid in grants}
                   if v.get("ledger") else None)
        return v["receipt"], grants, ledgers
    gid = v["grant"]["grant_id"]
    receipt = {"issuer_did": v.get("agent_did"), "issued_at": v["issued_at"],
               "receipt_id": v.get("receipt_id", ""), "action": v["action"], "authority_chain": [gid]}
    ledgers = {gid: LedgerContext.from_receipts(v["ledger"], gid)} if v.get("ledger") else None
    return receipt, {gid: v["grant"]}, ledgers


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_vector(path):
    v = json.loads(path.read_text())
    want_status, want_reason = v["expect"]

    if v["kind"] == "grant":
        ledger = LedgerContext.from_receipts(v["ledger"], v["grant"]["grant_id"]) if v.get("ledger") else None
        verdict = verify_grant(v["grant"], v["action"], v["issued_at"],
                               agent_did=v.get("agent_did"), receipt_id=v.get("receipt_id", ""),
                               ledger_context=ledger, revocation_checker=_revocation(v), **_policy(v))
    elif v["kind"] == "chain":
        receipt, grants, ledgers = _chain_inputs(v)
        verdict = verify_authority_chain(receipt, grants, ledger_contexts=ledgers,
                                         revocation_checker=_revocation(v), **_policy(v))
    else:
        pytest.fail(f"unknown vector kind {v['kind']!r}")

    assert verdict.status == want_status, f"{path.stem}: status {verdict.status} != {want_status} ({verdict.detail})"
    assert verdict.reason == want_reason, f"{path.stem}: reason {verdict.reason!r} != {want_reason!r}"


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_trace_aggregate_matches_verify_authority_chain(path):
    """verify_authority_chain is a wrapper around verify_authority_chain_trace
    — for every conformance vector, the two must return identical aggregates.
    ``grant`` vectors are lifted into a one-entry chain (see ``_chain_inputs``)
    so the whole corpus, not just the chain-kind vectors, exercises both entry
    points. Until 0.3.0 this test skipped every grant vector."""
    v = json.loads(path.read_text())
    receipt, grants, ledgers = _chain_inputs(v)
    kw = dict(ledger_contexts=ledgers, revocation_checker=_revocation(v), **_policy(v))

    direct = verify_authority_chain(receipt, grants, **kw)
    traced = verify_authority_chain_trace(receipt, grants, **kw).aggregate

    assert traced == direct, f"{path.stem}: trace aggregate {traced} != direct {direct}"


@pytest.mark.parametrize("path", [p for p in FILES if json.loads(p.read_text())["kind"] == "grant"],
                         ids=[p.stem for p in FILES if json.loads(p.read_text())["kind"] == "grant"])
def test_grant_vector_lifted_into_a_chain_keeps_its_verdict(path):
    """A receipt citing exactly one grant must reach the same (status, reason)
    the grant reaches alone: the chain walk adds ancestor checks, and a root
    grant has no ancestors, so nothing may change. (The one exception is the
    aggregate's SATISFIED, which carries no grant_id — only status and reason
    are compared.)"""
    v = json.loads(path.read_text())
    if (v["grant"].get("delegation") or {}).get("parent_grant_id"):
        pytest.skip("a child grant verified alone has no parent in the map; the chain walk "
                    "correctly reports grant_not_found, which is the point of the vector")
    want_status, want_reason = v["expect"]
    receipt, grants, ledgers = _chain_inputs(v)
    verdict = verify_authority_chain(receipt, grants, ledger_contexts=ledgers,
                                     revocation_checker=_revocation(v), **_policy(v))
    assert (verdict.status, verdict.reason) == (want_status, want_reason), f"{path.stem}: {verdict}"


def test_corpus_nonempty():
    assert FILES, "no conformance vectors found — run vectors/_generate.py"
