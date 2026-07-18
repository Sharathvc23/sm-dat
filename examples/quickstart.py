from sm_arp import Identity, build_action
from sm_dat import (LedgerContext, StaticRevocationList, build_grant, sign_grant,
                    verify_grant, check_attenuation)

principal, agent = Identity.generate(), Identity.generate()

grant = sign_grant(principal, build_grant(
    grantee_did=agent.did,
    action_categories=["purchase"],
    stateless={"amount_currency": "USD", "amount_cents_per_action_max": 5000,
               "counterparty_allowlist": ["domain:amctheatres.com"]},
    stateful={"amount_cents_per_period_max": 50000, "period": "month"},
    not_before="2026-04-01T00:00:00Z",
    not_after="2026-06-30T23:59:59Z",
    revocation={"list_url": "https://principal.example/revocations.json"},
    human_summary="Buy movie tickets, <=$50/mo, AMC only.",
))
# Note: the revocation gate runs only for grants that DECLARE a revocation
# source; a grant without one is never checker-consulted.

def buy(cents):
    return build_action(category="purchase", human_summary=f"{cents}c of tickets",
                        amount_cents=cents, currency="USD",
                        counterparty_label="domain:amctheatres.com")

ledger = LedgerContext.from_receipts([], grant["grant_id"])   # an empty agency log
WHEN = "2026-04-10T19:00:00Z"
live = StaticRevocationList([], fetched_at=WHEN)              # a fresh, empty revocation list

v = verify_grant(grant, buy(3000), WHEN, agent_did=agent.did,
                 ledger_context=ledger, revocation_checker=live)
print("in-bounds    :", v.status, v.reason)

v = verify_grant(grant, buy(9000), WHEN, agent_did=agent.did,
                 ledger_context=ledger, revocation_checker=live)
print("over cap     :", v.status, v.reason)

# The third outcome: this grant DECLARES a revocation source, so verifying
# without a checker refuses to guess — INDETERMINATE, never a silent pass.
v = verify_grant(grant, buy(3000), WHEN, agent_did=agent.did, ledger_context=ledger)
print("no checker   :", v.status, v.reason)

# And an actual revocation: True=revoked, False=known-live, None=cannot tell.
rl = StaticRevocationList([{"grant_id": grant["grant_id"], "revoked_at": "2026-04-05T00:00:00Z"}],
                          fetched_at=WHEN)
v = verify_grant(grant, buy(3000), WHEN, agent_did=agent.did,
                 ledger_context=ledger, revocation_checker=rl)
print("revoked      :", v.status, v.reason)

# Delegation with attenuation: a child grant may only narrow, never widen.
child = sign_grant(agent, build_grant(
    grantee_did=Identity.generate().did, action_categories=["purchase"],
    stateless={"amount_currency": "USD", "amount_cents_per_action_max": 2000,
               "counterparty_allowlist": ["domain:amctheatres.com"]},
    stateful={"amount_cents_per_period_max": 20000, "period": "month"},
    not_before="2026-04-01T00:00:00Z", not_after="2026-05-31T23:59:59Z",
    human_summary="Sub-delegate: <=$20.", parent_grant_id=grant["grant_id"]))
print("attenuation  :", check_attenuation(child, grant).status)
