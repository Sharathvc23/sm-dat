"""Sign a DAT and verify actions against it — the happy path and two rejections.

End to end:

  1. a principal signs a DAT granting an agent a bounded authority (purchase,
     <=$50/action, AMC only, MA/NY);
  2. the agent takes an in-scope action -> SATISFIED;
  3. an over-cap action -> VIOLATED(amount_cap_exceeded);
  4. an agent that mints its own key and self-issues a grant ->
     VIOLATED(self_grant) — authority must come from someone else.

Run:  python examples/grant_and_verify.py
"""

from __future__ import annotations

from sm_arp import build_action

from sm_dat import Identity, build_grant, sign_grant, verify_grant

PRINCIPAL = Identity.from_seed(b"\x01" * 32)
AGENT = Identity.from_seed(b"\x02" * 32)
WHEN = "2026-04-10T19:00:00Z"


def movie_grant() -> dict:
    return sign_grant(PRINCIPAL, build_grant(
        grantee_did=AGENT.did,
        action_categories=["purchase"],
        not_before="2026-04-01T00:00:00Z",
        not_after="2026-06-30T23:59:59Z",
        human_summary="Buy movie tickets, <=$50 each, AMC only, MA/NY.",
        stateless={
            "amount_currency": "USD",
            "amount_cents_per_action_max": 5000,
            "counterparty_allowlist": ["domain:amctheatres.com"],
            "jurisdictions": ["US-MA", "US-NY"],
        },
    ))


def buy(cents: int, *, where: str = "domain:amctheatres.com", region: str = "US-MA") -> dict:
    a = build_action(category="purchase", human_summary=f"{cents}c tickets",
                     amount_cents=cents, currency="USD", counterparty_label=where)
    a["jurisdiction"] = region
    return a


def main() -> None:
    grant = movie_grant()
    print("grant            :", grant["grant_id"])

    v = verify_grant(grant, buy(3000), WHEN, agent_did=AGENT.did)
    print("in-scope $30     :", v.status, f"({v.reason})")
    assert v.status == "SATISFIED"

    v = verify_grant(grant, buy(9000), WHEN, agent_did=AGENT.did)
    print("over-cap $90     :", v.status, f"({v.reason})")
    assert v.status == "VIOLATED" and v.reason == "amount_cap_exceeded"

    # The agent generates its own did:key and signs a grant to itself.
    self_grant = sign_grant(AGENT, build_grant(
        grantee_did=AGENT.did, action_categories=["purchase"],
        not_after="2026-06-30T23:59:59Z", human_summary="I authorize myself."))
    v = verify_grant(self_grant, buy(3000), WHEN, agent_did=AGENT.did)
    print("self-grant       :", v.status, f"({v.reason})")
    assert v.status == "VIOLATED" and v.reason == "self_grant"


if __name__ == "__main__":
    main()
