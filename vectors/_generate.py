"""Deterministically generate the dat/0.1 conformance corpus.

Run: ``python vectors/_generate.py``. Uses fixed seeds so signatures are stable
and the corpus is reproducible byte-for-byte. Each vector is one JSON file the
conformance test replays against the reference verifier.
"""

from __future__ import annotations

import copy
import json
import pathlib

from sm_arp import Identity, build_action

from sm_dat import build_grant, build_initial_bind, sign_grant

OUT = pathlib.Path(__file__).parent / "dat" / "0.1"
OUT.mkdir(parents=True, exist_ok=True)

P = Identity.from_seed(b"\x01" * 32)   # principal / grantor
A = Identity.from_seed(b"\x02" * 32)   # agent / grantee
A2 = Identity.from_seed(b"\x03" * 32)  # sub-agent
A3 = Identity.from_seed(b"\x04" * 32)  # unrelated third party (chain-discontinuity vectors)
PURCHASE = "2026-04-10T19:00:00Z"

vectors: list[dict] = []


def add(name, **v):
    v["name"] = name
    vectors.append(v)


def base_grant(**over):
    kw = dict(
        grantee_did=A.did,
        action_categories=["purchase"],
        not_after="2026-06-30T23:59:59Z",
        not_before="2026-04-01T00:00:00Z",
        human_summary="Buy movie tickets, <=$50 each, AMC only, MA/NY.",
        stateless={
            "amount_currency": "USD",
            "amount_cents_per_action_max": 5000,
            "counterparty_allowlist": ["domain:amctheatres.com"],
            "jurisdictions": ["US-MA", "US-NY"],
        },
    )
    kw.update(over)
    return sign_grant(P, build_grant(**kw))


def act(**over):
    kw = dict(category="purchase", human_summary="2 tickets",
              amount_cents=3000, currency="USD",
              counterparty_label="domain:amctheatres.com")
    kw.update(over)
    a = build_action(**{k: v for k, v in kw.items() if k != "jurisdiction"})
    if "jurisdiction" in kw:
        a["jurisdiction"] = kw["jurisdiction"]
    return a


G = base_grant()

# --- stateless: satisfied + each violation -------------------------------
add("stateless_satisfied", kind="grant", grant=G, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, expect=["SATISFIED", "ok"])
add("amount_cap_exceeded", kind="grant", grant=G, action=act(amount_cents=9000),
    issued_at=PURCHASE, agent_did=A.did, expect=["VIOLATED", "amount_cap_exceeded"])
add("amount_currency_mismatch", kind="grant", grant=G, action=act(currency="EUR"),
    issued_at=PURCHASE, agent_did=A.did, expect=["VIOLATED", "amount_currency_mismatch"])
add("counterparty_not_allowed", kind="grant", grant=G,
    action=act(counterparty_label="domain:scalpers.example"),
    issued_at=PURCHASE, agent_did=A.did, expect=["VIOLATED", "counterparty_not_allowed"])
add("jurisdiction_not_allowed", kind="grant", grant=G, action=act(jurisdiction="US-CA"),
    issued_at=PURCHASE, agent_did=A.did, expect=["VIOLATED", "jurisdiction_not_allowed"])
add("category_out_of_scope", kind="grant", grant=G,
    action=act(category="message_sent", amount_cents=None),
    issued_at=PURCHASE, agent_did=A.did, expect=["VIOLATED", "category_out_of_scope"])

# --- temporal ------------------------------------------------------------
add("expired", kind="grant", grant=G, action=act(jurisdiction="US-MA"),
    issued_at="2026-07-01T00:00:00Z", agent_did=A.did, expect=["VIOLATED", "expired"])
add("not_yet_valid", kind="grant", grant=G, action=act(jurisdiction="US-MA"),
    issued_at="2026-03-01T00:00:00Z", agent_did=A.did, expect=["VIOLATED", "not_yet_valid"])

# --- identity / structure ------------------------------------------------
add("grantee_mismatch", kind="grant", grant=G, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A2.did, expect=["VIOLATED", "grantee_mismatch"])

_tampered = copy.deepcopy(G)
_tampered["human_summary"] = "Buy ANYTHING, no limits."  # post-signature edit
add("bad_signature", kind="grant", grant=_tampered, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, expect=["VIOLATED", "bad_signature"])

_malformed = copy.deepcopy(G)
del _malformed["not_after"]
add("malformed_missing_field", kind="grant", grant=_malformed, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, expect=["VIOLATED", "malformed"])

# self-grant: agent generates its own did:key as grantor and issues itself a DAT.
# grantor == grantee → rejected outright, even though validly signed.
G_SELF = sign_grant(A, build_grant(
    grantee_did=A.did, action_categories=["purchase"], not_after="2026-06-30T23:59:59Z",
    not_before="2026-04-01T00:00:00Z", human_summary="I authorize myself to buy anything."))
add("self_grant", kind="grant", grant=G_SELF, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, expect=["VIOLATED", "self_grant"])

# --- stateful per-period caps -------------------------------------------
GB = base_grant(stateful={"amount_cents_per_period_max": 5000, "period": "month",
                          "period_anchor": "calendar"})
prior = [{"issued_at": "2026-04-02T10:00:00Z", "authority_chain": [GB["grant_id"]],
          "action": {"amount": {"cents": 3000, "currency": "USD"}}}]
add("period_under_cap", kind="grant", grant=GB, action=act(amount_cents=1000, jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, ledger=prior, expect=["SATISFIED", "ok"])
add("period_at_cap", kind="grant", grant=GB, action=act(amount_cents=2000, jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, ledger=prior, expect=["SATISFIED", "ok"])
add("period_over_cap", kind="grant", grant=GB, action=act(amount_cents=2001, jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, ledger=prior, expect=["VIOLATED", "period_cap_exceeded"])
add("period_missing_ledger_indeterminate", kind="grant", grant=GB,
    action=act(amount_cents=1000, jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, expect=["INDETERMINATE", "accounting_required"])

# tiebreak: a prior receipt with the SAME issued_at as the action. The total
# order (issued_at, receipt_id) decides whether it is "prior". Here the prior's
# receipt_id ("rcpt-aaaa") sorts before the action's ("rcpt-bbbb"), so it counts:
# 3000 prior + 3000 this = 6000 > 5000 cap → VIOLATED, deterministically.
same_ts_prior = [{"issued_at": PURCHASE, "receipt_id": "rcpt-aaaa",
                  "authority_chain": [GB["grant_id"]],
                  "action": {"amount": {"cents": 3000, "currency": "USD"}}}]
add("period_tiebreak_same_ts_counts_prior", kind="grant", grant=GB,
    action=act(amount_cents=3000, jurisdiction="US-MA"),
    issued_at=PURCHASE, receipt_id="rcpt-bbbb", agent_did=A.did, ledger=same_ts_prior,
    expect=["VIOLATED", "period_cap_exceeded"])
# Same data, but the action's receipt_id ("rcpt-0000") sorts BEFORE the peer's,
# so the peer is NOT prior and is excluded: 0 + 3000 <= 5000 → SATISFIED.
add("period_tiebreak_same_ts_excludes_later", kind="grant", grant=GB,
    action=act(amount_cents=3000, jurisdiction="US-MA"),
    issued_at=PURCHASE, receipt_id="rcpt-0000", agent_did=A.did, ledger=same_ts_prior,
    expect=["SATISFIED", "ok"])

# --- revocation ----------------------------------------------------------
GR = base_grant(revocation={"revocable_by": ["grantor"],
                            "revocation_lookup_uri": "https://issuer.example/dat/revocations",
                            "max_revocation_age_seconds": 86400})
fresh = "2026-04-10T12:00:00Z"
add("revocation_live", kind="grant", grant=GR, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did,
    revocation={"entries": [], "fetched_at": fresh, "max_age": 86400},
    expect=["SATISFIED", "ok"])
add("revocation_revoked_before", kind="grant", grant=GR, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did,
    revocation={"entries": [{"grant_id": GR["grant_id"], "revoked_at": "2026-04-09T00:00:00Z"}],
                "fetched_at": fresh, "max_age": 86400},
    expect=["VIOLATED", "revoked"])
add("revocation_revoked_after", kind="grant", grant=GR, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did,
    revocation={"entries": [{"grant_id": GR["grant_id"], "revoked_at": "2026-04-20T00:00:00Z"}],
                "fetched_at": fresh, "max_age": 86400},
    expect=["SATISFIED", "ok"])
add("revocation_stale_indeterminate", kind="grant", grant=GR, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did,
    revocation={"entries": [], "fetched_at": "2026-04-01T00:00:00Z", "max_age": 86400},
    expect=["INDETERMINATE", "revocation_unknown"])
add("revocation_no_checker_indeterminate", kind="grant", grant=GR, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, expect=["INDETERMINATE", "revocation_unknown"])

# --- predicate (no evaluator injected → INDETERMINATE) -------------------
GP = base_grant(predicate="action.amount.cents < 4000")
add("predicate_unsupported_indeterminate", kind="grant", grant=GP, action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did, expect=["INDETERMINATE", "predicate_unsupported"])

# --- initial-bind authorizes nothing -------------------------------------
G_BIND = sign_grant(P, build_initial_bind(
    grantee_did=A.did, not_before="2026-01-01T00:00:00Z", not_after="2026-12-31T23:59:59Z"))
add("initial_bind_authorizes_nothing", kind="grant", grant=G_BIND,
    action=act(jurisdiction="US-MA"),
    issued_at=PURCHASE, agent_did=A.did,
    expect=["VIOLATED", "initial_bind_authorizes_nothing"])

# --- sub-delegation / attenuation (chain vectors) ------------------------
PARENT = base_grant()
CHILD_OK = sign_grant(A, build_grant(
    grantee_did=A2.did, action_categories=["purchase"], not_after="2026-06-30T23:59:59Z",
    not_before="2026-04-01T00:00:00Z", human_summary="Sub: <=$30, AMC only.",
    stateless={"amount_currency": "USD", "amount_cents_per_action_max": 3000,
               "counterparty_allowlist": ["domain:amctheatres.com"]},
    parent_grant_id=PARENT["grant_id"]))
rcpt_child = {"issuer_did": A2.did, "issued_at": PURCHASE,
              "authority_chain": [CHILD_OK["grant_id"]],
              "action": act(amount_cents=2500, jurisdiction="US-MA")}
add("subdelegation_valid_narrowing", kind="chain", receipt=rcpt_child,
    grants=[PARENT, CHILD_OK], expect=["SATISFIED", "ok"])

CHILD_WIDE = sign_grant(A, build_grant(
    grantee_did=A2.did, action_categories=["purchase"], not_after="2026-06-30T23:59:59Z",
    not_before="2026-04-01T00:00:00Z", human_summary="Sub but wider cap.",
    stateless={"amount_currency": "USD", "amount_cents_per_action_max": 9000,
               "counterparty_allowlist": ["domain:amctheatres.com"]},
    parent_grant_id=PARENT["grant_id"]))
rcpt_wide = {"issuer_did": A2.did, "issued_at": PURCHASE,
             "authority_chain": [CHILD_WIDE["grant_id"]],
             "action": act(amount_cents=2500, jurisdiction="US-MA")}
add("subdelegation_widening_breach", kind="chain", receipt=rcpt_wide,
    grants=[PARENT, CHILD_WIDE], expect=["VIOLATED", "attenuation_breach"])

# An ancestor reached via parent_grant_id MUST be independently signature-
# verified, not just attenuation-checked. Same grant_id as the real PARENT,
# but content tampered post-signature (the "bad_signature" pattern above,
# applied to an ancestor instead of the entry grant).
PARENT_FORGED = copy.deepcopy(PARENT)
PARENT_FORGED["human_summary"] = "Buy ANYTHING, no limits."  # post-signature edit
add("subdelegation_forged_ancestor_signature", kind="chain", receipt=rcpt_child,
    grants=[PARENT_FORGED, CHILD_OK], expect=["VIOLATED", "bad_signature"])

# A child's grantor_did MUST equal its parent's grantee_did — otherwise the
# "chain" can splice in an ancestor from an unrelated delegation relationship.
# CHILD_SPLICED is validly signed and validly attenuates PARENT's scope, but
# its grantor (A3) never received anything from PARENT (which grants to A).
CHILD_SPLICED = sign_grant(A3, build_grant(
    grantee_did=A2.did, action_categories=["purchase"], not_after="2026-06-30T23:59:59Z",
    not_before="2026-04-01T00:00:00Z", human_summary="Sub: <=$30, AMC only.",
    stateless={"amount_currency": "USD", "amount_cents_per_action_max": 3000,
               "counterparty_allowlist": ["domain:amctheatres.com"]},
    parent_grant_id=PARENT["grant_id"]))
rcpt_spliced = {"issuer_did": A2.did, "issued_at": PURCHASE,
                "authority_chain": [CHILD_SPLICED["grant_id"]],
                "action": act(amount_cents=2500, jurisdiction="US-MA")}
add("subdelegation_chain_discontinuity", kind="chain", receipt=rcpt_spliced,
    grants=[PARENT, CHILD_SPLICED], expect=["VIOLATED", "chain_discontinuity"])

# --- multi-grant aggregation --------------------------------------------
G_A = base_grant()
G_B = sign_grant(P, build_grant(
    grantee_did=A.did, action_categories=["purchase"], not_after="2026-06-30T23:59:59Z",
    not_before="2026-04-01T00:00:00Z", human_summary="Second grant, AMC only.",
    stateless={"amount_currency": "USD", "amount_cents_per_action_max": 4000,
               "counterparty_allowlist": ["domain:amctheatres.com"]}))
rcpt_both = {"issuer_did": A.did, "issued_at": PURCHASE,
             "authority_chain": [G_A["grant_id"], G_B["grant_id"]],
             "action": act(amount_cents=3000, jurisdiction="US-MA")}
add("multigrant_all_satisfied", kind="chain", receipt=rcpt_both,
    grants=[G_A, G_B], expect=["SATISFIED", "ok"])

rcpt_one_bad = {"issuer_did": A.did, "issued_at": PURCHASE,
                "authority_chain": [G_A["grant_id"], G_B["grant_id"]],
                "action": act(amount_cents=4500, jurisdiction="US-MA")}  # busts G_B's 4000 cap
add("multigrant_one_violated", kind="chain", receipt=rcpt_one_bad,
    grants=[G_A, G_B], expect=["VIOLATED", "amount_cap_exceeded"])

G_STATE = base_grant(stateful={"amount_cents_per_period_max": 5000, "period": "month"})
rcpt_ind = {"issuer_did": A.did, "issued_at": PURCHASE,
            "authority_chain": [G_A["grant_id"], G_STATE["grant_id"]],
            "action": act(amount_cents=1000, jurisdiction="US-MA")}  # G_STATE needs ledger, none given
add("multigrant_one_indeterminate", kind="chain", receipt=rcpt_ind,
    grants=[G_A, G_STATE], expect=["INDETERMINATE", "accounting_required"])

# --- initial-bind is neutral in an authority_chain (§3.0) ----------------
# Alongside a real grant that authorizes: the real grant's SATISFIED propagates;
# the initial-bind neither blocks nor short-circuits.
rcpt_bind_ok = {"issuer_did": A.did, "issued_at": PURCHASE,
                "authority_chain": [G_BIND["grant_id"], G_A["grant_id"]],
                "action": act(amount_cents=3000, jurisdiction="US-MA")}
add("chain_initial_bind_neutral_real_satisfies", kind="chain", receipt=rcpt_bind_ok,
    grants=[G_BIND, G_A], expect=["SATISFIED", "ok"])

# Alongside a real grant that DENIES: the real grant's verdict propagates and the
# initial-bind does NOT short-circuit the chain to pass (catches that bug).
rcpt_bind_deny = {"issuer_did": A.did, "issued_at": PURCHASE,
                  "authority_chain": [G_BIND["grant_id"], G_A["grant_id"]],
                  "action": act(amount_cents=9000, jurisdiction="US-MA")}  # busts G_A's $50 cap
add("chain_initial_bind_no_shortcircuit_real_denies", kind="chain", receipt=rcpt_bind_deny,
    grants=[G_BIND, G_A], expect=["VIOLATED", "amount_cap_exceeded"])

# Only an initial-bind in the chain → nothing authorizes it. Fail closed.
rcpt_bind_only = {"issuer_did": A.did, "issued_at": PURCHASE,
                  "authority_chain": [G_BIND["grant_id"]],
                  "action": act(amount_cents=3000, jurisdiction="US-MA")}
add("chain_initial_bind_only_authorizes_nothing", kind="chain", receipt=rcpt_bind_only,
    grants=[G_BIND], expect=["VIOLATED", "initial_bind_authorizes_nothing"])


def main():
    for f in OUT.glob("*.json"):
        f.unlink()
    for i, v in enumerate(vectors):
        (OUT / f"{i:02d}-{v['name']}.json").write_text(json.dumps(v, indent=2, sort_keys=True))
    print(f"wrote {len(vectors)} vectors to {OUT}")


if __name__ == "__main__":
    main()
