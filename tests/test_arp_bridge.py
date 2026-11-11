"""End-to-end across both packages: sm-arp's verify_authority_chain resolves a
DAT referenced by an authority_granted receipt and delegates the rich evaluation
to sm-dat's verifier via make_dat_verifier. Requires sm-arp >= 0.3.0 (the bridge).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sm_arp import build_action, dat_grant_payload, issue_receipt, verify_authority_chain, verify_direct_grant

from sm_dat import Identity, LedgerContext, build_grant, make_dat_verifier, sign_grant

P = Identity.from_seed(b"\x01" * 32)   # principal / grantor
A = Identity.from_seed(b"\x02" * 32)   # agent / grantee
WHEN = "2026-04-10T19:00:00Z"


def movie_dat(grantor: Identity = P) -> dict[str, Any]:
    return sign_grant(grantor, build_grant(
        grantee_did=A.did, action_categories=["purchase"],
        not_before="2026-04-01T00:00:00Z", not_after="2026-06-30T23:59:59Z",
        human_summary="Buy tickets, <=$50, AMC only.",
        stateless={"amount_currency": "USD", "amount_cents_per_action_max": 5000,
                   "counterparty_allowlist": ["domain:amctheatres.com"]}))


def grant_receipt(dat: dict[str, Any]) -> dict[str, Any]:
    return issue_receipt(P, principal_did=P.did, action=build_action(
        category="authority_granted", human_summary="Granted the movie DAT.",
        machine_payload=dat_grant_payload(dat)))


def action_receipt(grant_receipt_id: str, *, cents: int) -> dict[str, Any]:
    return issue_receipt(A, principal_did=P.did, issued_at=WHEN, action=build_action(
        category="purchase", human_summary="tickets", amount_cents=cents, currency="USD",
        counterparty_label="domain:amctheatres.com", granted_by_receipt_id=grant_receipt_id))


def test_in_scope_action_authorized_end_to_end():
    dat = movie_dat()
    g = grant_receipt(dat)
    r = action_receipt(g["receipt_id"], cents=3000)
    res = verify_authority_chain(
        r, {g["receipt_id"]: g},
        dats={dat["grant_id"]: dat}, dat_verifier=make_dat_verifier())
    assert res.ok


def test_over_cap_action_denied_and_reason_preserved():
    dat = movie_dat()
    g = grant_receipt(dat)
    r = action_receipt(g["receipt_id"], cents=9000)  # busts the $50 cap
    res = verify_authority_chain(
        r, {g["receipt_id"]: g},
        dats={dat["grant_id"]: dat}, dat_verifier=make_dat_verifier())
    assert not res.ok and res.detail == "violated:amount_cap_exceeded"


def test_stateful_without_ledger_fails_closed_as_indeterminate():
    # A per-period cap with no ledger context: sm-dat returns INDETERMINATE,
    # which the binary sm-arp chain collapses to not-ok, reason preserved.
    dat = sign_grant(P, build_grant(
        grantee_did=A.did, action_categories=["purchase"],
        not_before="2026-04-01T00:00:00Z", not_after="2026-06-30T23:59:59Z",
        human_summary="<=$50/month.", stateless={"amount_currency": "USD"},
        stateful={"amount_cents_per_period_max": 5000, "period": "month"}))
    g = grant_receipt(dat)
    r = action_receipt(g["receipt_id"], cents=1000)
    res = verify_authority_chain(
        r, {g["receipt_id"]: g},
        dats={dat["grant_id"]: dat}, dat_verifier=make_dat_verifier())  # no ledger supplied
    assert not res.ok and res.detail == "indeterminate:accounting_required"


def test_stateful_with_ledger_decides():
    dat = sign_grant(P, build_grant(
        grantee_did=A.did, action_categories=["purchase"],
        not_before="2026-04-01T00:00:00Z", not_after="2026-06-30T23:59:59Z",
        human_summary="<=$50/month.", stateless={"amount_currency": "USD"},
        stateful={"amount_cents_per_period_max": 5000, "period": "month"}))
    g = grant_receipt(dat)
    r = action_receipt(g["receipt_id"], cents=1000)
    spent = [{"issued_at": "2026-04-02T10:00:00Z", "receipt_id": "rcpt-prior",
              "authority_chain": [dat["grant_id"]],
              "action": {"amount": {"cents": 3000, "currency": "USD"}}}]
    verifier = make_dat_verifier(
        ledger_contexts={dat["grant_id"]: LedgerContext.from_receipts(spent, dat["grant_id"])})
    res = verify_authority_chain(r, {g["receipt_id"]: g}, dats={dat["grant_id"]: dat},
                                 dat_verifier=verifier)
    assert res.ok  # 3000 + 1000 <= 5000

def test_direct_grant_checks_dat_owner_with_real_signatures():
    at = datetime.fromisoformat(WHEN)
    for signer in (P, Identity.generate()):
        dat = movie_dat(signer)
        grant = issue_receipt(P, principal_did=P.did, issued_at=WHEN, action=build_action(
            category="authority_granted", human_summary="Movie purchase",
            machine_payload=dat_grant_payload(dat)))
        action = action_receipt(grant["receipt_id"], cents=3000)
        result = verify_direct_grant(action, grant, at=at, require_dat=True,
                                     dats={dat["grant_id"]: dat}, dat_verifier=make_dat_verifier())
        assert result.ok == (signer.did == P.did)


def test_bridge_passes_policy_switches_through():
    # The bridge already binds grantor to principal_did (grantor_mismatch);
    # trusted_grantors narrows further and require_revocation_source refuses a
    # DAT that declares no revocation source — both preserved as reasons.
    dat = movie_dat()
    g = grant_receipt(dat)
    r = action_receipt(g["receipt_id"], cents=3000)
    ok = make_dat_verifier(trusted_grantors={P.did})
    assert verify_authority_chain(r, {g["receipt_id"]: g}, dats={dat["grant_id"]: dat}, dat_verifier=ok).ok
    narrowed = make_dat_verifier(trusted_grantors={A.did})
    res = verify_authority_chain(r, {g["receipt_id"]: g}, dats={dat["grant_id"]: dat}, dat_verifier=narrowed)
    assert not res.ok and res.detail == "violated:untrusted_grantor"
    strict = make_dat_verifier(require_revocation_source=True)
    res = verify_authority_chain(r, {g["receipt_id"]: g}, dats={dat["grant_id"]: dat}, dat_verifier=strict)
    assert not res.ok and res.detail == "violated:no_revocation_source"
