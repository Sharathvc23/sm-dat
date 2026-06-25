# Predicate Annex — `scope.predicate` (DRAFT)

> **Status: DRAFT / NON-NORMATIVE in `dat/0.1`.** The *injection seam* ships in 0.1
> (`verify_grant(..., predicate_evaluator=…)`); this annex sketches the evaluator that
> seam expects and will be normalized in `0.2`. `0.1` conformance requires only correct
> handling of the seam (no evaluator ⇒ INDETERMINATE; false ⇒ VIOLATED; raise ⇒
> INDETERMINATE), not a working evaluator.

## Purpose

The fixed `stateless`/`stateful` constraint vocabulary (SPEC §4.1–§4.2) is intentionally
small and deterministic so conformance is byte-stable. Some grants need a predicate the
vocabulary cannot express — conditional triggers, compound logic, relations between fields.
`scope.predicate` is the capability-gated escape hatch, carried as a **CEL**
([Common Expression Language](https://github.com/google/cel-spec)) string and evaluated by
an **injected** evaluator. It is fenced so it can never weaken the deterministic core: a
verifier that does not inject an evaluator simply returns `INDETERMINATE`.

## Evaluator contract

```
predicate_evaluator(predicate: str, grant: dict, action: dict) -> bool
```

- returns `True`  → the predicate is satisfied; verification continues.
- returns `False` → `VIOLATED(predicate_failed)`.
- raises          → `INDETERMINATE(predicate_error)`. A broken evaluator must never pass.

## Evaluation context (proposed, 0.2)

A CEL evaluator is given a read-only context:

| Binding | Value |
|---------|-------|
| `action` | the action under test (category, `amount.cents`, `amount.currency`, `counterparty_label`, `counterparty_did`, `jurisdiction`) |
| `grant` | the DAT envelope (scope, window, grantor/grantee) |
| `now` | the action's `issued_at` (RFC 3339), so time predicates are pinned to the receipt, not wall-clock |

Example: `action.amount.cents < 4000 && action.jurisdiction in ['US-MA','US-NY']`.

## Determinism requirements (proposed, 0.2)

For predicate verdicts to be recomputable by any party (SPEC §5.2), the evaluator MUST be:

- **Pure** — no clock, no RNG, no I/O, no network. Time comes only from `now` in the
  context.
- **Total over the documented context** — referencing an absent field yields `false`
  (fail-closed), not an error, unless explicitly using a presence test.
- **Bounded** — a complexity/time bound so a hostile predicate cannot wedge a verifier.

A conformance sub-corpus (satisfied / violated / fail-closed-on-missing-field / evaluator
bound exceeded) accompanies the normative annex in `0.2`.

## Why injected, not bundled

Bundling a CEL engine would pull an expression evaluator into a trust primitive whose whole
value is deterministic, recomputable verdicts. Keeping it injected means: the core stays
dependency-free and byte-stable; the predicate path is opt-in per verifier; and an
implementation can choose a CEL engine it trusts (or a stricter subset) without the library
dictating one.
