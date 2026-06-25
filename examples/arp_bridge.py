"""End-to-end across sm-arp + sm-dat: a completed ARP receipt is checked for
authorization against a DAT it references, with the rich evaluation delegated to
sm-dat. Requires sm-arp >= 0.3.0.

  1. the principal signs a DAT (purchase, <=$50, AMC only);
  2. the principal issues an `authority_granted` ARP receipt that references the
     DAT by id + digest (dat_grant_payload);
  3. the agent acts, citing the grant in its own receipt;
  4. any third party calls sm_arp.verify_authority_chain with sm-dat's verifier
     injected — the chain resolves the DAT, checks the digest, and richly
     evaluates the action. No enforcement point was in the loop.

Run:  python examples/arp_bridge.py
"""

from __future__ import annotations

from sm_arp import build_action, dat_grant_payload, issue_receipt, verify_authority_chain

from sm_dat import Identity, build_grant, make_dat_verifier, sign_grant

P = Identity.from_seed(b"\x01" * 32)
A = Identity.from_seed(b"\x02" * 32)
WHEN = "2026-04-10T19:00:00Z"


def main() -> None:
    dat = sign_grant(P, build_grant(
        grantee_did=A.did, action_categories=["purchase"],
        not_before="2026-04-01T00:00:00Z", not_after="2026-06-30T23:59:59Z",
        human_summary="Buy tickets, <=$50, AMC only.",
        stateless={"amount_currency": "USD", "amount_cents_per_action_max": 5000,
                   "counterparty_allowlist": ["domain:amctheatres.com"]}))

    grant_r = issue_receipt(P, principal_did=P.did, action=build_action(
        category="authority_granted", human_summary="Granted the movie DAT.",
        machine_payload=dat_grant_payload(dat)))
    print("grant receipt    :", grant_r["receipt_id"], "→ DAT", dat["grant_id"][:32], "…")

    verifier = make_dat_verifier()

    for cents in (3000, 9000):
        action_r = issue_receipt(A, principal_did=P.did, issued_at=WHEN, action=build_action(
            category="purchase", human_summary="tickets", amount_cents=cents, currency="USD",
            counterparty_label="domain:amctheatres.com",
            granted_by_receipt_id=grant_r["receipt_id"]))
        res = verify_authority_chain(action_r, {grant_r["receipt_id"]: grant_r},
                                     dats={dat["grant_id"]: dat}, dat_verifier=verifier)
        verdict = "AUTHORIZED" if res.ok else f"DENIED ({res.detail})"
        print(f"${cents/100:>6.2f} purchase :", verdict)

    # 3000 authorized; 9000 denied with the rich reason carried through sm-arp.
    assert verify_authority_chain(
        issue_receipt(A, principal_did=P.did, issued_at=WHEN, action=build_action(
            category="purchase", human_summary="t", amount_cents=3000, currency="USD",
            counterparty_label="domain:amctheatres.com",
            granted_by_receipt_id=grant_r["receipt_id"])),
        {grant_r["receipt_id"]: grant_r}, dats={dat["grant_id"]: dat}, dat_verifier=verifier).ok


if __name__ == "__main__":
    main()
