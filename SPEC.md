# DAT — Delegated Authority Token

**Spec version:** `dat/0.1-draft`
**Status:** DRAFT. Normative intent, but not frozen. Published parallel to ARP v0.2.
**Companion to:** [ARP — Agency Receipt Protocol](https://github.com/Sharathvc23/sm-arp) (`authority_chain` field, §4.6 `authority_granted`).
**Signing/identity substrate:** reused from `sm_arp` — JCS canonicalization, Ed25519, `did:key`.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted as in RFC 2119.

---

## 1. Introduction

ARP records *what an agent did*. DAT records *what an agent was allowed to do*. Together they
answer the two halves of every accountability question — **"did this happen?"** (ARP) and
**"was it authorized?"** (DAT).

A **DAT** is a portable, cryptographically signed grant from a **principal** (human or
organisation) to an **agent**, authorizing a bounded set of action categories, for a bounded
period, under bounded conditions. A DAT is signed by the **grantor's** key — this is the single
defining distinction from an ARP receipt, which is signed by the *agent*. A DAT is therefore a
non-repudiable statement by the human: *"I permitted this."*

### 1.1 Scope of this library

`sm-dat` owns exactly four things:

1. The **DAT envelope** — its canonical fields, types, and constraints (§3).
2. The **scope/constraint model** — the vocabulary an action is checked against (§4).
3. The **verification decision procedure** — the function that, given a DAT, an action, and
   (optionally) a ledger context, returns SATISFIED / VIOLATED / INDETERMINATE (§5).
4. The **attenuation rule** for sub-delegation (§6).

It does **not** own: identity (`sm-arp`/`did:key`), the receipt of the action (`sm-arp`),
reputation (`sm-parc`), synchronous human approval (`sm-oversight`), or the agent's internal
capability sandbox (`sm-airlock`). See §10 for the ownership map.

### 1.2 Why a separate library

DAT is adjacent to OAuth scopes, WebAuthn, `did:key`, and W3C Verifiable Credentials but is
none of them. Bundling it into ARP would make ARP sprawling; it deserves its own envelope, its
own verification algorithm, and its own conformance corpus. `sm-dat` depends on `sm-arp` for
crypto primitives the way `sm-parc` does — it never re-implements signing.

---

## 2. Terminology

| Term | Meaning |
|------|---------|
| **Grantor** | The principal who issues and signs the DAT. The authority originates here. |
| **Grantee** | The agent the DAT authorizes. Identified by `did:key`. |
| **Grant** | A single DAT instance. |
| **Scope** | The set of action categories + constraints the grant permits. |
| **Constraint** | A single predicate over an action (amount cap, allowlist, jurisdiction, …). |
| **Verifier** | Any party that checks whether an action was authorized. Usually the action's counterparty or an auditor. |
| **Ledger context** | The set of prior receipts citing a grant, needed to evaluate *stateful* (per-period) constraints. |
| **Verdict** | One of `SATISFIED`, `VIOLATED`, `INDETERMINATE`, with a machine reason code. |

---

## 3. The DAT envelope

```json
{
  "version": "dat/0.1",
  "grant_id": "dat:did:key:z6Mki...:movies-budget-grant-q2",
  "grantor_did": "did:key:z6Mki...",
  "grantee_did": "did:key:z6Mktw...",
  "issued_at": "2026-04-01T00:00:00Z",
  "not_before": "2026-04-01T00:00:00Z",
  "not_after":  "2026-06-30T23:59:59Z",
  "human_summary": "Lets my assistant buy movie tickets, up to $50/mo, from AMC or Fandango, in MA or NY.",
  "scope": {
    "action_categories": ["purchase"],
    "stateless": {
      "amount_currency": "USD",
      "amount_cents_per_action_max": 5000,
      "counterparty_allowlist": ["domain:amctheatres.com", "domain:fandango.com", "merchant_category:7832"],
      "jurisdictions": ["US-MA", "US-NY"]
    },
    "stateful": {
      "amount_cents_per_period_max": 50000,
      "period": "month",
      "period_anchor": "calendar"
    },
    "predicate": null
  },
  "delegation": {
    "parent_grant_id": null,
    "max_depth": 4
  },
  "revocation": {
    "revocable_by": ["grantor", "grantor.guardian"],
    "revocation_lookup_uri": "https://issuer.example/dat/revocations",
    "max_revocation_age_seconds": 86400
  },
  "authorization_ceremony": null,
  "signature": "z3Mv8k..."
}
```

### 3.0 Initial bind

Before any explicit grant exists, the principal↔agent relationship is recorded as an
**initial-bind** DAT: `scope.action_categories` empty and `"initial_bind": true`, signed by
the principal at registration. It is deliberately **fail-closed** — it authorizes *nothing*
that requires a DAT; it only attests that the binding exists. An action verified against an
initial-bind grant alone is `VIOLATED(initial_bind_authorizes_nothing)`, a distinct verdict
from *no grant at all* (which surfaces as `no_authority_chain`). Build it with
`build_initial_bind`.

In an `authority_chain` (§5.3) an initial-bind grant is **neutral**: it neither authorizes nor
blocks, so the real grants decide and it MUST NOT short-circuit the chain to authorized. A chain
whose only grant is initial-bind is unauthorized.

### 3.1 Required fields

`version`, `grant_id`, `grantor_did`, `grantee_did`, `issued_at`, `not_before`, `not_after`,
`human_summary`, `scope.action_categories` (non-empty), and `signature` MUST be present. A DAT
missing any of these is malformed and MUST verify as `VIOLATED(malformed)`.

### 3.2 Field notes

- **`grant_id`** — globally unique, stable, opaque. Convention: `dat:<grantor_did>:<sha256(grant)[:16]>`. It
  is the value an ARP receipt cites in its `authority_chain`.
- **`human_summary`** — REQUIRED, ≤ 280 chars. Learning from ARP: a grant the principal cannot
  read is a grant the principal cannot meaningfully give. `alt_summaries` (array of
  `{lang, summary}`) MAY carry translations, same length bound each.
- **`not_before` / `not_after`** — RFC 3339. An action whose receipt `issued_at` falls outside
  `[not_before, not_after]` is `VIOLATED`.
- **`scope`** — split into `stateless` and `stateful` (§4). This split is normative: it is what
  lets a verifier know whether it can decide with the DAT alone.
- **`predicate`** — OPTIONAL advanced constraint (§4.4). `null` ⇒ no predicate.
- **`delegation`** — sub-delegation metadata (§6). `parent_grant_id: null` ⇒ a root grant.
- **`authorization_ceremony`** — OPTIONAL. Records how the human authenticated when signing
  (e.g. a WebAuthn/passkey attestation reference). Out of normative scope in `0.1`; reserved.
- **`signature`** — Ed25519 over the JCS-canonical envelope with `signature` removed, by
  `grantor_did`'s key (§8).

> **Grantor control is a precondition the library cannot enforce.** A valid signature proves only
> that whoever holds `grantor_did`'s key signed the grant — *not* that `grantor_did` is the human
> principal rather than the agent. The security of a DAT is entirely contingent on the verifier
> establishing that `grantor_did` is controlled by the actual human principal, not by the grantee
> agent. `did:key` is necessary but **not sufficient** for this. The library rejects the literal
> `grantor_did == grantee_did` self-grant (§5.1, step 1a), but cannot detect an agent that mints a
> *second* `did:key` it secretly controls and uses as grantor. Closing that gap is the job of
> `authorization_ceremony` (a WebAuthn/passkey attestation binding the signature to a human
> ceremony), reserved here and normalized in `0.2`. Until then, **callers MUST establish
> grantor-to-human binding out of band** (e.g. registration-time identity proofing).

---

## 4. Scope and constraints

The constraint model is split by what a verifier needs to evaluate it. **This split is the
central design decision of `sm-dat`** — it keeps the common case a pure function and makes the
stateful case honest about its data dependency.

### 4.1 Stateless constraints (decidable from DAT + single action)

Checked with only the DAT and the one action under review. A pure function — no ledger, no
network. The normative `0.1` vocabulary:

| Constraint | Semantics |
|-----------|-----------|
| `amount_currency` + `amount_cents_per_action_max` | The action's amount MUST be in this currency and ≤ this cap. |
| `counterparty_allowlist` | The action's counterparty MUST match ≥ 1 entry. Entry forms: `domain:<host>`, `did:<key>`, `merchant_category:<mcc>`. Empty/absent ⇒ no counterparty restriction. |
| `jurisdictions` | The action's jurisdiction MUST be in this set (ISO 3166-2 codes). Absent ⇒ no jurisdiction restriction. |

All stateless constraints present MUST hold (AND). A constrained field that the action does not
carry is a `VIOLATED` — fail closed, never assume.

### 4.2 Stateful constraints (require a ledger context)

Per-period cumulative limits. These are **not** a pure function of one action — the verifier
MUST sum the action against prior actions that cited this same `grant_id` within the period
window.

| Constraint | Semantics |
|-----------|-----------|
| `amount_cents_per_period_max` + `period` (`day`\|`week`\|`month`) | Σ(prior satisfied actions citing this grant in the window) + this action MUST be ≤ cap. |
| `period_anchor` (`calendar`\|`rolling`) | `calendar`: window is the containing calendar day/week/month. `rolling`: window is `[issued_at − period, issued_at]`. |

**Critical rule:** if a DAT carries any stateful constraint and the verifier is **not** given a
ledger context, verification MUST return `INDETERMINATE(accounting_required)`. It MUST NOT
return `SATISFIED`. A budget you could not compute is a budget you cannot vouch for. This
mirrors `sm-parc`'s "recompute, don't trust" discipline.

**Total ordering (determinism).** A per-period sum requires a total order on receipts to decide
which are "prior" to the action under test. Receipts are ordered by the tuple
**`(issued_at, receipt_id)` ascending** — `issued_at` first, ties broken by `receipt_id`
lexicographically (the same tiebreak `sm-parc` uses for Merkle-leaf ordering). A receipt `R`
counts toward the window for action `X` iff `R` falls in the period window **and**
`(R.issued_at, R.receipt_id) < (X.issued_at, X.receipt_id)`. Without the tiebreak, two receipts
sharing an `issued_at` (real under high-frequency agents) would each see the other as not-prior
and both admit, busting the cap. The sum of amounts is itself commutative — the order matters
only for this boundary membership, which is exactly where it must be pinned.

### 4.3 Currency

All amount math is integer cents in a single currency per grant (`amount_currency`). Cross-
currency grants are out of scope for `0.1`; issue separate grants per currency.

### 4.4 Optional predicate (advanced, capability-gated)

For conditions the fixed vocabulary cannot express (conditional triggers, compound logic), a
DAT MAY carry `scope.predicate` as a **CEL** ([Common Expression Language]) string evaluated
against a defined action context. Rules:

- The evaluator is **injected**, not bundled: `verify_grant(..., predicate_evaluator=…)` takes a
  `(predicate, grant, action) -> bool` callable. The library ships none, so the deterministic
  core carries no expression engine.
- A verifier with no evaluator injected MUST treat a non-null `predicate` as
  `INDETERMINATE(predicate_unsupported)` — never silently ignore it.
- A predicate evaluating to `false` ⇒ `VIOLATED(predicate_failed)`. An evaluator that *raises*
  ⇒ `INDETERMINATE(predicate_error)` — a broken evaluator must not pass.
- The CEL context, function set, and determinism requirements are specified in
  [`docs/predicate-annex.md`](docs/predicate-annex.md) (draft; full normative annex is `0.2`).
  `0.1` conformance does not require predicate support; it requires correct INDETERMINATE/
  VIOLATED handling of the seam.

> **Why not CEL for everything?** A full expression evaluator invites implementation divergence
> and breaks byte-deterministic conformance. The fixed `stateless`/`stateful` vocabulary is the
> normative core every implementation MUST agree on; CEL is an opt-in escape hatch, fenced off
> so it cannot weaken the guarantees of the core.

---

## 5. Verification

`verify_grant(dat, action, issued_at, *, agent_did, receipt_id="", ledger_context=None,
revocation_checker=None, predicate_evaluator=None, require_revocation_source=False,
trusted_grantors=None)` returns a **Verdict**: a status in `{SATISFIED, VIOLATED, INDETERMINATE}`
plus a reason code. `agent_did` — the acting agent, i.e. the receipt's `issuer_did` — is
**required**: a grant is a statement about a grantee, and a verdict that never compared the actor
to the grantee vouches for nobody. A caller that does not know the actor passes `None` and gets
`INDETERMINATE(grantee_unbound)`.

Two relying-party switches tighten the defaults; neither loosens anything:

| Option | Default | Effect when set |
|--------|---------|-----------------|
| `require_revocation_source: bool` | `False` | A grant (or any ancestor, §6) that declares no `revocation` is `VIOLATED(no_revocation_source)`. The default keeps 0.1's rule — the revocation gate runs only for grants that declare a source — which makes a grant with `revocation: null` irrevocable by omission; a relying party that will not accept that sets this. |
| `trusted_grantors: set[str] \| None` | `None` | The **root** grantor of authority MUST be in the set, else `VIOLATED(untrusted_grantor)`. This is the library-side half of obligation O1 (§5.4). `verify_grant` applies it to a root grant directly; for a child grant it cannot see the root and answers `INDETERMINATE(root_grantor_unresolved)` — the chain walk (§5.3, §6) resolves the root and applies the set there. An empty set trusts nobody. |

### 5.1 Ordered decision procedure

Checks run in order; the first non-SATISFIED result short-circuits and is returned.

1. **Structure** — all required fields present and well-typed, else `VIOLATED(malformed)`.
   "Well-typed" includes every timestamp: the grant's `issued_at`, `not_before`, `not_after` and
   the action's `issued_at` MUST be RFC 3339 **with a UTC offset** (a naive timestamp would be
   read in the verifier's local zone, making the verdict depend on where it runs). A timestamp
   that does not parse is `VIOLATED(malformed)` with the field named in `detail` — a verdict,
   never an exception escaping the decision procedure.
1a. **Self-grant** — `grantor_did != grantee_did`, else `VIOLATED(self_grant)`. An agent cannot
    authorize itself; authority must originate with another party. Checked *before* signature so
    a validly-signed self-grant still fails. (This catches only the literal case — see the
    grantor-control precondition in §3.2 for the deeper one the library cannot detect.)
2. **Signature** — `dat.signature` verifies over the JCS-canonical envelope under
   `grantor_did`'s key, else `VIOLATED(bad_signature)`.
2a. **Grantor trust** — if `trusted_grantors` is supplied: a root grant's `grantor_did` MUST be
    in it, else `VIOLATED(untrusted_grantor)`; a child grant ⇒
    `INDETERMINATE(root_grantor_unresolved)` (the chain walk decides, §6).
3. **Grantee** — `agent_did` absent ⇒ `INDETERMINATE(grantee_unbound)`; present and not equal to
   `grantee_did` ⇒ `VIOLATED(grantee_mismatch)`.
4. **Temporal** — `not_before ≤ issued_at ≤ not_after`, else
   `VIOLATED(not_yet_valid | expired)`.
5. **Revocation** — if `revocation` is present:
   - with a `revocation_checker`: if `grant_id` is revoked as of `issued_at` ⇒
     `VIOLATED(revoked)`.
   - without a checker, or the checker cannot produce a list fresher than
     `max_revocation_age_seconds` ⇒ `INDETERMINATE(revocation_unknown)`.
   If `revocation` is absent and `require_revocation_source` is set ⇒
   `VIOLATED(no_revocation_source)`; otherwise an undeclared source is not checked.
6. **Category** — `action.category ∈ scope.action_categories`, else
   `VIOLATED(category_out_of_scope)`.
7. **Stateless constraints** (§4.1) — each present constraint holds, else
   `VIOLATED(<constraint>)`.
8. **Stateful constraints** (§4.2) — if present and `ledger_context is None` ⇒
   `INDETERMINATE(accounting_required)`; else compute the window sum and check the cap, else
   `VIOLATED(period_cap_exceeded)`.
9. **Predicate** (§4.4) — if non-null: unsupported ⇒ `INDETERMINATE(predicate_unsupported)`;
   false ⇒ `VIOLATED(predicate_failed)`.
10. **Sub-delegation** (§6) — if `delegation.parent_grant_id` is set, the parent chain MUST
    independently authorize the action under attenuation, else propagate its verdict. This step
    is performed by the chain walk in `verify_authority_chain` (which has the `grants` map);
    `verify_grant` alone evaluates the one grant it is handed.

If all checks pass ⇒ `SATISFIED`.

### 5.2 Three outcomes, not two

`INDETERMINATE` is first-class and MUST NOT be collapsed into either pass or fail by the
library. It is the verifier's signal that it lacks data (a ledger, a fresh revocation list, a
predicate evaluator) to decide. Policy on what to *do* with INDETERMINATE (fail-closed, fetch
and retry, escalate to `sm-oversight`) belongs to the *caller*, not to `sm-dat`. The library's
job is to never claim a guarantee it cannot recompute.

### 5.3 Composing multiple grants (`authority_chain`)

An ARP receipt's `authority_chain` MAY list several `grant_id`s. The action is **authorized**
iff every cited non-`initial_bind` grant returns `SATISFIED` — none `VIOLATED`, none
`INDETERMINATE` — and at least one grant actually authorizes the action. Aggregation:

- any grant `VIOLATED` ⇒ action `UNAUTHORIZED` (and surface which).
- else any grant `INDETERMINATE` ⇒ action `INDETERMINATE`.
- **`initial_bind` grants are neutral** — skipped (§3.0): they neither authorize nor block,
  so the real grants decide. They MUST NOT short-circuit the chain to `AUTHORIZED`.
- at least one non-`initial_bind` grant `SATISFIED` (and none `VIOLATED`) ⇒ `AUTHORIZED`.
- a chain with no authorizing grant — empty, or only `initial_bind` — ⇒ `UNAUTHORIZED`
  (`initial_bind_authorizes_nothing` when an initial-bind was present, else `no_authority_chain`).

`verify_authority_chain(receipt, grants, ...)` implements this. **Note:** `sm-arp` already ships
a same-named `verify_authority_chain` against a *thinner* model (see §9.1) — `sm-dat`'s version
supersedes it for DAT-envelope grants; the ARP one remains for backward compatibility.

### 5.3a Per-node trace

`verify_authority_chain_trace(receipt, grants, ...)` runs the identical
decision procedure as `verify_authority_chain` (§5.3) and returns the same
aggregate `Verdict`, plus a `chains` structure: one leaf-to-root list of
per-grant results per `authority_chain` entry. Every entry is walked and
recorded, including entries after an earlier one has already violated —
`chains` reflects the whole receipt, not just however far a pass/fail
short-circuit reached. `verify_authority_chain` is defined in terms of this
function: `verify_authority_chain(...) == verify_authority_chain_trace(...).aggregate`,
for every well-formed input the two entry points share.

Walking every entry means a grant this function reaches can be one the
pre-refactor `verify_authority_chain`'s short-circuit would never have
touched — including a grant malformed enough to trip an internal error mid-
walk (e.g. a non-dict `delegation` field). Such an entry is reported as
`VIOLATED(malformed_grant)` rather than raising; this is the one reason
code in this module produced by a catch-all rather than a specific
structural check.

### 5.4 Verifier obligations

`sm-dat`'s guarantees hold only as far as the inputs the verifier supplies. The library decides
*"does this grant authorize this action?"* — it cannot establish the facts that question rests
on. Each obligation below is something the library **assumes and cannot check**; the verifier
MUST establish it, and where it cannot, MUST treat the result as `INDETERMINATE` (or reject) —
never as an implicit pass. A reviewer should be able to check all four at a glance.

| # | The library assumes… | The verifier MUST… | If it cannot |
|---|----------------------|--------------------|--------------|
| **O1 — Grantor is the human** | `grantor_did` is controlled by the actual principal, not the grantee agent (§3.2). A valid signature proves only key-possession. | Bind `grantor_did` to the human out of band (registration-time identity proofing; later, `authorization_ceremony`). `did:key` is necessary, not sufficient. Then **tell the library**: pass the bound DIDs as `trusted_grantors` so the root grantor is asserted, not assumed (§5). The ARP bridge (`make_dat_verifier`, §9) binds the grantor to the receipt's `principal_did` automatically. | Reject. An unbound grantor makes every downstream check meaningless. |
| **O2 — Ledger is complete** | The `LedgerContext` for a stateful cap contains **every** prior receipt citing the grant within the window (§4.2). | Supply a ledger known-complete for the period. A partial ledger *undercounts* and can wrongly admit an over-budget action. | Return `INDETERMINATE(accounting_required)`; do not pass on a ledger you cannot vouch is complete. |
| **O3 — Order is well-defined** | Every receipt carries a stable `receipt_id`, so the total order `(issued_at, receipt_id)` is defined (§4.2). | Ensure receipts have unique `receipt_id`s and feed them through unchanged. | Treat tied-timestamp receipts as undecidable → `INDETERMINATE`, not a guessed order. |
| **O4 — Timestamps are trustworthy** | `action.issued_at` is the true time of the action. It is **agent-asserted** — the ARP receipt signature covers it, but the agent chose it. | Corroborate `issued_at` where it gates a decision (window membership, expiry, per-period caps). A backdated/forward-dated timestamp can slip an action inside a grant window or dodge a cap. See ARP's threat model. | Where the timestamp cannot be corroborated and the decision turns on it, prefer `INDETERMINATE` or escalate (e.g. `sm-oversight`). |

These obligations are the seam between `sm-dat` and its host. They are deliberately *not*
encoded as silent defaults: a trust primitive that quietly assumes its preconditions hold is one
that fails open. `sm-dat` fails closed — it surfaces what it could not verify and leaves the
policy to the caller (§5.2).

---

## 6. Sub-delegation and attenuation

A DAT MAY grant a narrower DAT (agent → sub-agent), enabling delegation chains. The security
invariant is **attenuation: a child grant's scope MUST be a subset of its parent's. A child can
only ever narrow, never broaden.**

- `delegation.parent_grant_id` links a child to its parent; each link is recorded in the ARP
  receipt's `authority_chain`.

### 6.1 Attenuation table

`check_attenuation(child, parent)` — for every dimension the child MUST be at least as
restrictive. **Any** widening at **any** link ⇒ `VIOLATED(attenuation_breach)` (the dimension
is named in `detail`).

| Dimension | Rule (child vs parent) | Note |
|-----------|------------------------|------|
| `scope.action_categories` | `⊆` | |
| `stateless.amount_cents_per_action_max` | `≤` | child omitting a cap the parent has is a widening |
| `stateless.amount_currency` | `=` (when the parent sets one) | a cap is denominated; dropping or changing the currency re-denominates the bound |
| `stateless.counterparty_allowlist` | `⊆` (when the parent sets one) | child omitting it is a widening |
| `stateless.jurisdictions` | `⊆` (when the parent sets one) | child omitting it is a widening |
| `stateful.amount_cents_per_period_max` | `≤` | |
| `scope.predicate` | identical string (when the parent sets one) | 0.1 has no predicate algebra to decide "narrower"; a child MUST carry its parent's predicate verbatim |
| `not_before` | `≥` | a child may not start before its parent |
| `not_after` | `≤` | a child may not outlive its parent |
| `delegation.max_depth` | `≤` (absent ⇒ 4) | the bound is the principal's to set; a leaf cannot lift it |

A grant whose timestamps or structure cannot be read is `VIOLATED(malformed)`, never an
exception. Attenuation is checked structurally from the grants themselves — it does not require
the ledger.

### 6.2 Chain walk algorithm

Given an `authority_chain` entry `gid` (the **leaf**) and the `grants` map, a verifier MUST:

1. **Leaf structure** — `_structure(leaf)` (§5.1 step 1) and the action's `issued_at`, else
   `VIOLATED(malformed)`.
2. **Walk leaf → root** along `parent_grant_id`. At each link, with `child` the current grant
   and `parent` the one it names, stop at the first non-SATISFIED result:
   1. `parent_grant_id` already visited ⇒ `VIOLATED(chain_cycle)` (a cycle has no root).
   2. parent not in `grants` ⇒ `VIOLATED(grant_not_found)`.
   3. parent fails structure (§5.1 step 1) ⇒ `VIOLATED(malformed)`.
   4. parent `grantor_did == grantee_did` ⇒ `VIOLATED(self_grant)`.
   5. **Every ancestor is a distinct signed grant, not a trusted data record**: parent signature
      fails ⇒ `VIOLATED(bad_signature)`. An unsigned or forged ancestor reached this way is exactly
      as dangerous as one presented as the entry grant.
   6. **Continuity** — `child.grantor_did ≠ parent.grantee_did` ⇒ `VIOLATED(chain_discontinuity)`
      (closes splicing an ancestor from an unrelated delegation relationship).
   7. **Attenuation** — `check_attenuation(child, parent)` (§6.1) ⇒ `VIOLATED(attenuation_breach)`.
   8. **Ancestor window** — at the action's `issued_at`: `issued_at < parent.not_before` ⇒
      `VIOLATED(ancestor_not_yet_valid)`; `issued_at > parent.not_after` ⇒
      `VIOLATED(ancestor_expired)`. An ancestor outside its window had no authority to delegate
      at that moment, however well the child narrows.
   9. **Ancestor revocation** — same gate as §5.1 step 5, on the parent's `grant_id`: declared
      source + no checker, or checker cannot resolve ⇒ `INDETERMINATE(revocation_unknown)`;
      revoked as of `issued_at` ⇒ `VIOLATED(ancestor_revoked)`; no declared source and
      `require_revocation_source` ⇒ `VIOLATED(no_revocation_source)`. A revoked parent cannot
      lend authority to a child.
3. **Depth** — with `depth` the number of links walked and the bound read from the **root**
   grant's `delegation.max_depth` (absent ⇒ 4): `depth > max_depth` ⇒ `VIOLATED(depth_exceeded)`.
   The bound MUST NOT be read from the leaf: the leaf is signed by the delegating agent, who could
   set it arbitrarily. Because `max_depth` is an attenuated dimension (§6.1), the root's value is
   also the chain's maximum.
4. **Root grantor** — if `trusted_grantors` is supplied and the root's `grantor_did` is not in
   it ⇒ `VIOLATED(untrusted_grantor)`. The root is the only grantor whose trust is a question: every
   other link's grantor is a grantee one level up, already bound by continuity.
5. **Leaf** — only if every step above passed, run `verify_grant` on the leaf (§5.1) with the
   receipt's `issuer_did` as `agent_did`; this is the entry's verdict. If the walk stopped
   earlier, the walk's verdict is the entry's and the leaf is reported `INDETERMINATE(not_evaluated)`
   in the trace rather than guessed.

A chain is only as trustworthy as its weakest link: attenuation-only checking (narrowing scope)
says nothing about whether an ancestor is real, belongs to this delegation relationship, was
valid at the time, or had already been revoked.

---

## 7. Revocation

`0.1` minimum-viable model: a grantor publishes a **signed revocation list** at
`revocation_lookup_uri`. Each entry: `{grant_id, revoked_at, reason?}`, the whole list signed by
the grantor (or a `revocable_by` delegate). A verifier:

- treats a grant as revoked iff an entry with `revoked_at ≤ action.issued_at` exists;
- requires a list no older than `max_revocation_age_seconds`; a stale or unreachable list ⇒
  `INDETERMINATE(revocation_unknown)` (§5.1.5), never an implicit pass.

**Prefer narrow `not_after` over revocation where possible** — a short-lived grant needs no
network call to expire. Distributed/CRL-style and transparency-log revocation are deferred to
`0.2+`.

---

## 8. Canonicalization and signature

Identical to ARP, by reuse of `sm_arp`:

1. Remove `signature`.
2. Canonicalize with JCS (RFC 8785).
3. Ed25519-sign the canonical bytes with the **grantor's** key.
4. `signature` is the multibase-encoded signature; the verifier re-derives the grantor key from
   `grantor_did` (`did:key`) and checks it.

A DAT and an ARP receipt are byte-compatible in their crypto envelope; a conformant `sm-dat`
verifier and the ARP signing path MUST agree on the canonical bytes.

---

## 9. Integration with ARP

- An ARP receipt asserts authorization by listing grant IDs in `action.authority_chain`.
- ARP §4.6's `authority_granted` action is itself the *issuance event* of a DAT (the on-network
  record that a grant was made); the DAT is the artifact, the `authority_granted` receipt is its
  ARP-logged emission.
- To verify an action was authorized, a verifier: (1) `verify_receipt` (ARP — did it happen,
  validly signed), then (2) `verify_authority_chain` (DAT — was it permitted). Both MUST pass.
- **The adapter (shipped).** `sm_arp.verify_authority_chain(receipt, grants, *, dats=, dat_verifier=)`
  (sm-arp ≥ 0.3.0) delegates rich evaluation to an injected callback. `sm_dat.make_dat_verifier(…)`
  builds that callback, mapping the three-valued `Verdict` onto sm-arp's binary `VerifyResult`
  **fail-closed** — SATISFIED → ok; VIOLATED *and* INDETERMINATE → not-ok, with `"<status>:<reason>"`
  preserved in `detail`. So an sm-arp authority-chain check passes only what sm-dat could
  positively vouch for.

### 9.1 Relationship to ARP v0.1's `authority_granted` (the thin model it supersedes)

ARP v0.1 already carries a minimal authorization mechanism: an `authority_granted` **receipt**
whose `machine_payload` holds a flat `granted_scope` (category list) + `grant_expires_at` +
`granted_to_did`, checked by `sm_arp.verify_authority_chain`. That is a v0.1 stopgap — it has no
amount caps, allowlists, jurisdictions, per-period budgets, sub-delegation, or attenuation.

DAT is the richer envelope that subsumes it. The migration:

- The `authority_granted` receipt remains the *on-network issuance event* — but its
  `machine_payload` SHOULD carry a `dat_grant_id` (and a `dat_digest`) referencing the full DAT
  envelope, rather than inlining a flat scope.
- A verifier resolves the referenced DAT and runs `sm_dat.verify_grant` (rich, three-valued)
  instead of ARP's flat scope check. ARP's thin path stays valid for grants that never adopt DAT.
- `granted_scope` in an `authority_granted` receipt and a DAT's `scope.action_categories` MUST
  agree on categories when both are present; a mismatch is `VIOLATED(scope_disagreement)`.

---

## 10. Ownership map (what sm-dat is *not*)

| Question | Library |
|----------|---------|
| Who is this agent? | `sm-arp` / `did:key` |
| Did this action happen, signed by the agent? | `sm-arp` |
| **Was this action permitted by the principal?** | **`sm-dat`** |
| Is this agent trustworthy (reputation)? | `sm-parc` |
| Approve this *specific* action, human-in-the-loop, now? | `sm-oversight` |
| What may this agent's *plugins/attributes* touch? | `sm-airlock` |
| Does this action comply with regulation? | `sm-locp` |

Clean seams: `sm-oversight` is *synchronous per-action* approval; `sm-dat` is *standing
autonomous* authorization granted ahead of time. `sm-airlock` is the agent's own sandbox;
`sm-dat` is the principal's leash. None overlap.

---

## 11. Library API (Python, `sm_dat`)

```python
from sm_arp import Identity, build_action          # reuse — no new crypto
from sm_dat import (
    build_grant, sign_grant, verify_grant, verify_authority_chain,
    LedgerContext, Verdict,
)

principal = Identity.generate()
agent     = Identity.generate()

grant = sign_grant(principal, build_grant(
    grantee_did=agent.did,
    action_categories=["purchase"],
    stateless={"amount_currency": "USD", "amount_cents_per_action_max": 5000,
               "counterparty_allowlist": ["domain:amctheatres.com"]},
    stateful={"amount_cents_per_period_max": 50000, "period": "month"},
    not_before="2026-04-01T00:00:00Z",
    not_after="2026-06-30T23:59:59Z",
    human_summary="Buy movie tickets, ≤$50/mo, AMC only.",
))

action = build_action(category="purchase", human_summary="2 tickets",
                      amount_cents=3000, currency="USD",
                      counterparty_label="domain:amctheatres.com")

v: Verdict = verify_grant(grant, action, "2026-04-10T19:00:00Z", agent_did=agent.did,
                          ledger_context=LedgerContext.from_receipts([], grant["grant_id"]))
assert v.status == "SATISFIED"        # or VIOLATED / INDETERMINATE, with v.reason
```

| Surface | Role |
|---------|------|
| `build_grant(...)` | Construct an unsigned envelope (validates structure). |
| `sign_grant(grantor, grant)` | JCS-canonicalize + Ed25519-sign by the grantor. |
| `verify_grant(grant, action, issued_at, *, agent_did, receipt_id="", ledger_context=None, revocation_checker=None, predicate_evaluator=None, require_revocation_source=False, trusted_grantors=None)` | The §5 decision procedure → `Verdict`. `agent_did` is required (0.3.0). |
| `verify_authority_chain(receipt, grants, *, ledger_contexts=None, revocation_checker=None, predicate_evaluator=None, require_revocation_source=False, trusted_grantors=None)` | §5.3 multi-grant aggregation over a completed receipt, with the §6.2 chain walk per entry. Supersedes ARP's thinner same-named check for DAT-envelope grants (§9.1). |
| `verify_authority_chain_trace(receipt, grants, ...)` | §5.3a: same aggregate plus the per-node `chains` trace. Same keyword options. |
| `make_dat_verifier(*, ledger_contexts=None, revocation_checker=None, predicate_evaluator=None, require_revocation_source=False, trusted_grantors=None)` | §9: the `dat_verifier` callback for `sm_arp.verify_authority_chain`. Binds `grantor_did` to the receipt's `principal_did` before anything else. |
| `parse_rfc3339(ts)` | The verifier's timestamp parser: aware UTC datetime, or `None` for anything that is not an RFC 3339 string with an offset. Never raises. |
| `LedgerContext` | Holds prior receipts and sums by `grant_id` + window. `from_receipts(receipts, grant_id)` filters in memory — the ARP store (`ReceiptLog`/`AgencyLog`) only `append`s today, so a future upstream `ReceiptLog.by_grant(grant_id, window)` would slot in here without changing callers. |
| `verify_grant_signature(grant)` | Just the JCS/Ed25519 signature check (a `verify_grant` stage, exposed alone). |
| `check_attenuation(child, parent)` | §6.1: a child grant may only narrow — every scope dimension, both window ends, currency, predicate and `max_depth`. |
| `StaticRevocationList(entries, *, fetched_at, max_age_seconds=86400)` | A revocation checker over a fetched list: revoked / known-live / **stale ⇒ None (INDETERMINATE)**. |
| `build_initial_bind(...)` | §3.3: the principal↔agent binding grant — authorizes nothing by itself. |
| `Verdict` | `{status, reason, grant_id, detail}` — never a bare bool. |

*Not in 0.1:* a `GrantStore` (persistent grant/revocation-list store for grantors) is
roadmap — grants and revocation lists are plain dicts/lists you persist yourself today.

Dependencies: `sm-arp` (identity, canonicalization, signature, Agency Log), `jcs`,
`cryptography`. No transport, no framework.

---

## 12. Conformance (corpus plan)

Mirroring ARP's 22-vector approach — a JSON corpus, each vector `{grant, action, issued_at,
ledger_context?, expected_verdict, expected_reason}`, asserted byte-for-byte against the
reference verifier. Minimum coverage for `0.1`:

- one vector per stateless constraint, satisfied and violated;
- per-period cap: under, at, over, **missing ledger ⇒ INDETERMINATE**, and the
  **same-`issued_at` tiebreak** decided deterministically both ways by `receipt_id`;
- **self-grant** (`grantor_did == grantee_did`) ⇒ `VIOLATED(self_grant)`;
- **initial-bind** (§3.0): verified alone ⇒ `VIOLATED(initial_bind_authorizes_nothing)`; in an
  `authority_chain` alongside a real grant ⇒ the real grant's verdict propagates (SATISFIED when
  it authorizes, its `VIOLATED` reason when it denies) and the initial-bind neither blocks nor
  short-circuits to pass; a chain of *only* initial-bind ⇒ `VIOLATED(initial_bind_authorizes_nothing)`;
- expiry (before / within / after), not-yet-valid;
- revocation: active, revoked-before-action, revoked-after-action, stale-list ⇒ INDETERMINATE;
- attenuation: valid narrowing, and each widening dimension ⇒ attenuation_breach (incl.
  `not_before`, `amount_currency`, `predicate`, `max_depth`);
- depth exceeded — bound read from the **root**, with a within-bound control; a leaf declaring a
  larger `max_depth` than its root ⇒ attenuation_breach; a `parent_grant_id` cycle ⇒ chain_cycle;
- ancestor checks in the chain walk: ancestor_revoked, ancestor revocation with no checker ⇒
  INDETERMINATE, ancestor live, ancestor_not_yet_valid, ancestor_expired;
- policy switches: `require_revocation_source` (refused / satisfied, incl. on an ancestor),
  `trusted_grantors` (untrusted / trusted, on a root and on a chain's root, and a child grant
  verified alone ⇒ root_grantor_unresolved); `agent_did=None` ⇒ grantee_unbound;
- malformed timestamps (action `issued_at`, grant `not_before` without offset, grant
  `not_after`) ⇒ malformed, as verdicts;
- multi-grant aggregation: all-satisfied, one-violated, one-indeterminate;
- malformed envelopes; bad signature; grantee mismatch;
- non-null predicate on a non-predicate verifier ⇒ INDETERMINATE.

The negative and INDETERMINATE cases are the point — they are where an over-eager verifier
silently grants authority it cannot justify.

---

## 13. Deferred to `0.2`

Full predicate (CEL) annex + a reference evaluator (the injection seam ships in `0.1`;
[`docs/predicate-annex.md`](docs/predicate-annex.md) is draft) · WebAuthn/passkey
`authorization_ceremony` normalization · distributed/transparency-log revocation ·
cross-currency grants · normative freeze in lockstep with ARP v0.2.

(The ARP-side `dat_grant_id` bridge is implemented in `sm-arp` — `dat_digest`,
`dat_grant_payload`, and `verify_authority_chain(..., dats=, dat_verifier=)`; §9.1. The
`dat:initial-bind` implicit grant ships in `0.1` via `build_initial_bind`; §3.0.)

[Common Expression Language]: https://github.com/google/cel-spec
