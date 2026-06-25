# Contributing to sm-dat

Contributions are accepted under the Developer Certificate of Origin (DCO)
sign-off model. Add `Signed-off-by: Your Name <you@example.com>` to every commit
(`git commit -s`).

## Change process

1. Open a PR that updates the **spec (`SPEC.md`), the conformance vectors, and any
   affected code together**. Drift between these is a defect — the vectors under
   `vectors/dat/0.1/` and the `tests/` suite are the authoritative behavioural
   specification.
2. Regenerate vectors with `python vectors/_generate.py` and commit the result;
   CI fails if `vectors/` drifts from the generator.
3. CI runs the conformance corpus and the examples on Python 3.11 and 3.12. PRs
   that change existing vectors must either (a) update them with rationale in the
   PR description or (b) be rejected.
4. Every new guarantee needs a happy-path vector; every new rejection and every
   new `INDETERMINATE` reason needs its own vector. The negative and
   INDETERMINATE cases are the point.

## House rules

- **`INDETERMINATE` must never be collapsed** into a pass or a fail by the
  library. If the verifier lacks the data to decide (no ledger, stale revocation,
  no predicate evaluator), it says so — the caller owns the policy.
- **No new crypto.** Identity, canonicalization, and signatures are reused from
  `sm-arp`. Do not re-implement them.
- **No expansion of the envelope or verification surface without an RFC-style PR
  to `SPEC.md` first.**
- **No domain- or deployment-specific content** — this is a generic primitive.
- Keep the core dependency-free and deterministic: optional engines (e.g. a CEL
  predicate evaluator) are *injected*, never bundled.

## Local checks before pushing

```sh
pip install -e ".[dev]"
python -m pytest -q                 # conformance corpus + unit tests
python vectors/_generate.py && git diff --exit-code vectors/   # reproducible
python examples/grant_and_verify.py # examples must run
```

## What goes here vs. companions

- The DAT envelope, the verification procedure, the vectors, and the
  `sm-arp` bridge adapter — here.
- The receipt format (ARP), reputation (PARC), human approval (sm-oversight) —
  their own repos. See `GOVERNANCE.md` for the full scope boundary.
