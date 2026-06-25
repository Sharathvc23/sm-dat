# DAT — Delegated Authority Token — Whitepaper

## Abstract

When an agent acts for a human, two questions decide whether the action is legitimate:
*did it happen?* and *was it allowed?* The Agency Receipt Protocol (ARP) answers the
first with a signed receipt. DAT answers the second. A DAT is a portable,
principal-signed grant — what an agent may do, for how long, under what limits — and a
verifier checks an action against it. The contribution is not that grants exist;
OAuth-style scopes have existed for years. It is *how the check behaves*: DAT produces a
**three-valued, post-hoc, recomputable verdict** from an action plus a ledger context,
anchored to a completed receipt and reproducible by any third party, with no live
enforcement point in the loop. Authorization becomes a property of the record, checkable
by a stranger, rather than a transient decision that exists only at call time.

## 1. Problem

The agent stack has good answers for identity (who is this agent?), capability (what can
it do?), and reputation (is it trustworthy?). Authorization — *what did its principal
actually permit?* — is usually answered at runtime by a policy-enforcement point that
returns a binary permit/deny and then forgets. That decision is invisible afterward: a
counterparty receiving a completed action, or an auditor reviewing it a month later, has
no artifact to recompute. And a permit/deny that must answer *now* has no honest way to
say "I don't have the data to decide" — so it guesses, and a guess on a budget cap fails
open. What is missing is a grant whose verification is an artifact: deterministic,
after-the-fact, and honest about what it could not compute.

## 2. Design axioms

1. **Recompute, don't trust.** Authorization is decided by re-evaluating the action
   against the signed grant — never by trusting an enforcement point's earlier say-so.
   The verdict is a pure function of `(grant, action, ledger context)`.
2. **One signing path.** A DAT is Ed25519 over JCS — identical to ARP receipts and PARC
   credentials — signed by the **grantor**, not the agent. No new crypto enters the
   stack; the distinction from a receipt is *whose* key signs.
3. **Three outcomes, never two.** A verdict is `SATISFIED`, `VIOLATED`, or
   `INDETERMINATE`, and the library never collapses the third into a pass or a fail.
   INDETERMINATE is the signal that the verifier lacked the data to decide; what to *do*
   with it is the caller's policy, not the primitive's guess.
4. **Fail closed.** Where a decision turns on data the verifier does not hold — a ledger,
   a fresh revocation list, a predicate evaluator — the answer is INDETERMINATE, not an
   optimistic pass. A guarantee you cannot recompute is not a guarantee.

## 3. The authorization primitive

A DAT is the smallest envelope that makes "the principal permitted this" portable and
checkable: a grantor DID, a grantee DID, a validity window, and a **scope** — signed by
the grantor. Verification, `verify_grant(grant, action, …)`, is a single ordered
procedure returning the three-valued verdict.

Scope is split by what a verifier needs to evaluate it — and this split is the heart of
the design:

- **Stateless constraints** (per-action amount cap, counterparty allowlist, jurisdiction)
  are decidable from the grant and one action. A pure function: no ledger, no network.
- **Stateful constraints** (per-period budgets — "≤ $50/month") are *not* a function of
  one action. They require summing the action against prior actions that cited the same
  grant, under a defined total order `(issued_at, receipt_id)`.

### 3.1 INDETERMINATE is first-class — the per-period cap that refuses to guess

A per-period budget needs the ledger. Presented without it, `verify_grant` returns
`INDETERMINATE(accounting_required)` — literally *"I cannot decide without the ledger, and
I refuse to guess."* It does **not** silently pass. This is the axiom made concrete: a
binary permit/deny enforcement point, asked the same question without the running total,
either blocks the call or defers to an external decision point; it has no vocabulary for
*"the answer is computable, but not by me, not now."* DAT does, and treats that state as a
result a caller can act on (fetch the ledger and retry, or escalate to human oversight),
not an error to swallow.

### 3.2 Receipt-anchored verification

`verify_authority_chain(receipt, grants)` decides authorization against a **completed ARP
receipt** — after the action, by any third party, offline, with no policy-enforcement
point in the loop. This inverts the usual model. Runtime enforcement answers *before* the
call and leaves nothing behind; DAT answers *from the record*, so authorization is an
auditable property of what happened, re-checkable by a counterparty who was never in the
request path and by an auditor reviewing the ledger later. The grant's terms can live off
the receipt ledger; an `authority_granted` receipt commits to the DAT by digest, so the
cheap on-network record and the rich off-ledger terms cannot be separated or swapped.

Multiple grants compose: an action is authorized iff *every* grant in its
`authority_chain` is SATISFIED; any VIOLATED denies; else any INDETERMINATE is propagated.
Sub-delegation narrows only — a child grant's scope must be a subset of its parent's, so
authority can attenuate down a chain but never widen.

## 4. Composition with the portfolio

```
  ARP (receipt)        DAT (grant)              verify_authority_chain
  what an agent did    what the principal       (receipt + grants → 3-valued verdict)
  — agent-signed       permitted — grantor-      ┌─────────────────────────────────┐
        │              signed, scoped, bounded   │ SATISFIED / VIOLATED /            │
        └──────────────────────┬─────────────────│ INDETERMINATE  — post-hoc,        │
                               │                 │ recomputable, no PEP in the loop  │
   sm-oversight ───────────────┤                 └─────────────────────────────────┘
   per-action human approval   │
   (synchronous, in-loop)      ├──► PARC (standing) — reputation a stranger recomputes
                               │
   sm-conformance ─────────────┘    (Ed25519 / JCS signing pattern, shared by all)
```

DAT is the *standing, autonomous* counterpart to `sm-oversight`'s *synchronous,
per-action* approval: a DAT is what lets an agent act within bounds **without** pinging a
human each time; oversight is the fallback when no grant covers the action. Against ARP it
is the exact mirror — receipt (did it happen) ↔ grant (was it allowed) — which is why it
is a separate primitive rather than a field inside ARP: different signer, different
verification, different conformance corpus.

## 5. Open questions

- **Grantor-to-human binding.** A valid signature proves key-possession, not that the
  grantor DID is the human rather than the agent. The library rejects the literal
  self-grant (`grantor == grantee`); it cannot detect an agent that mints a second key it
  controls. Closing this is `authorization_ceremony` — a WebAuthn/passkey attestation
  binding the signature to a human ceremony — reserved in 0.1, normalized in 0.2. Until
  then it is a stated verifier obligation (SPEC §5.4).
- **Scope predicates.** A fixed constraint vocabulary keeps conformance deterministic;
  conditions it cannot express are reserved for an optional, capability-gated CEL
  predicate, fenced so it can never weaken the core. The evaluation context and its
  conformance vectors are 0.2 work.
- **Revocation transport.** 0.1 specifies a grantor-hosted signed list with a freshness
  bound (stale ⇒ INDETERMINATE); distributed/transparency-log revocation is a follow-up.

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
