"""The per-period budget cap that refuses to guess, and receipt-anchored verification.

This is DAT's headline behaviour:

  1. a grant with a per-period cap ($50/month) is presented to a verifier with
     NO ledger -> INDETERMINATE(accounting_required). It does not guess and it
     does not pass — a budget you cannot compute is a budget you cannot vouch for.
  2. given the ledger of prior receipts, the same check decides for real:
     under cap -> SATISFIED; over cap -> VIOLATED(period_cap_exceeded).
  3. verify_authority_chain checks authorization against a COMPLETED ARP receipt
     — after the fact, by any third party, with no enforcement point in the loop.

Run:  python examples/budget_and_indeterminate.py
"""

from __future__ import annotations

from sm_arp import build_action

from sm_dat import (
    Identity, LedgerContext, build_grant, sign_grant, verify_authority_chain, verify_grant,
)

PRINCIPAL = Identity.from_seed(b"\x01" * 32)
AGENT = Identity.from_seed(b"\x02" * 32)
WHEN = "2026-04-10T19:00:00Z"


def budget_grant() -> dict:
    return sign_grant(PRINCIPAL, build_grant(
        grantee_did=AGENT.did,
        action_categories=["purchase"],
        not_before="2026-04-01T00:00:00Z",
        not_after="2026-06-30T23:59:59Z",
        human_summary="Groceries, <=$50/month total.",
        stateless={"amount_currency": "USD"},
        stateful={"amount_cents_per_period_max": 5000, "period": "month", "period_anchor": "calendar"},
    ))


def buy(cents: int) -> dict:
    return build_action(category="purchase", human_summary=f"{cents}c groceries",
                        amount_cents=cents, currency="USD")


def prior_receipt(cents: int, rid: str, grant_id: str) -> dict:
    return {"issued_at": "2026-04-02T10:00:00Z", "receipt_id": rid,
            "authority_chain": [grant_id],
            "action": {"amount": {"cents": cents, "currency": "USD"}}}


def main() -> None:
    grant = budget_grant()

    # 1. No ledger -> the verifier refuses to guess.
    v = verify_grant(grant, buy(1000), WHEN, agent_did=AGENT.did)
    print("no ledger        :", v.status, f"({v.reason})")
    assert v.status == "INDETERMINATE" and v.reason == "accounting_required"

    # 2. With the ledger ($30 already spent this month), the cap is real.
    spent = [prior_receipt(3000, "rcpt-0001", grant["grant_id"])]
    ledger = LedgerContext.from_receipts(spent, grant["grant_id"])

    v = verify_grant(grant, buy(1000), WHEN, agent_did=AGENT.did, ledger_context=ledger)
    print("under cap (+$10) :", v.status, f"({v.reason})")
    assert v.status == "SATISFIED"

    v = verify_grant(grant, buy(2500), WHEN, agent_did=AGENT.did, ledger_context=ledger)
    print("over cap (+$25)  :", v.status, f"({v.reason})")
    assert v.status == "VIOLATED" and v.reason == "period_cap_exceeded"

    # 3. Receipt-anchored: a completed ARP receipt cites the grant. Any third
    #    party re-checks authorization from the record alone.
    receipt = {
        "version": "arp/0.1", "receipt_id": "rcpt-0002", "issuer_did": AGENT.did,
        "principal_did": PRINCIPAL.did, "issued_at": WHEN,
        "authority_chain": [grant["grant_id"]],
        "action": buy(1000), "signature": "AA==",
    }
    v = verify_authority_chain(receipt, {grant["grant_id"]: grant},
                               ledger_contexts={grant["grant_id"]: ledger})
    print("receipt-anchored :", v.status, f"({v.reason})", "— checked after the fact, no PEP")
    assert v.status == "SATISFIED"


if __name__ == "__main__":
    main()
