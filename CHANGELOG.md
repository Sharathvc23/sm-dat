# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-25

Initial release of sm-dat (private phase; publish pending), promoted from `sm-arp`'s `dat-companion.md` sketch.

### Added
- **ARP bridge adapter** (`make_dat_verifier`, SPEC §9.1) — builds the
  `dat_verifier` callback for `sm_arp.verify_authority_chain(..., dats=, dat_verifier=)`
  (requires sm-arp ≥ 0.3.0). Maps the three-valued `Verdict` onto sm-arp's binary
  `VerifyResult` fail-closed (VIOLATED *and* INDETERMINATE → not-ok, reason preserved).
  Completes the bridge end-to-end across both packages. (Closes #1.) Depends on `sm-arp>=0.3.0`.
- **`dat:initial-bind`** (`build_initial_bind`, SPEC §3.0) — the implicit, fail-closed
  principal↔agent bind recorded at registration. Empty scope; authorizes nothing requiring
  a DAT. An action against it alone is `VIOLATED(initial_bind_authorizes_nothing)`, distinct
  from "no grant at all". In an `authority_chain` it is **neutral** — neither authorizes nor
  blocks; the real grants decide and it never short-circuits the chain to authorized. (Closes #3.)
- **Predicate evaluator seam** (SPEC §4.4, `docs/predicate-annex.md`) —
  `verify_grant(..., predicate_evaluator=…)` injects a `(predicate, grant, action) -> bool`
  evaluator. None injected ⇒ `INDETERMINATE(predicate_unsupported)`; false ⇒
  `VIOLATED(predicate_failed)`; raises ⇒ `INDETERMINATE(predicate_error)`. The library bundles
  no expression engine, keeping the core deterministic. (Advances #2; full CEL annex is 0.2.)
- **Delegated Authority Token envelope.** A portable, grantor-signed grant — grantee,
  validity window, and a scope of action categories with constraints. Construct with
  `build_grant`; sign with `sign_grant` (Ed25519 over JCS, reusing `sm_arp`, signed by the
  **grantor** not the agent).
- **Three-valued verification.** `verify_grant(grant, action, …)` returns
  `SATISFIED` / `VIOLATED` / `INDETERMINATE` and never collapses INDETERMINATE into a pass
  or a fail. The verdict is a pure function of `(grant, action, ledger context)`.
- **Stateless / stateful scope split.** Stateless constraints (per-action amount cap,
  counterparty allowlist, jurisdiction) decide from the grant and one action; stateful
  constraints (per-period budgets) require a ledger.
- **`accounting_required` fail-closed.** A per-period cap presented without a ledger
  returns `INDETERMINATE(accounting_required)` — it refuses to guess. Window membership
  uses the total order `(issued_at, receipt_id)` so the sum is deterministic under
  tied timestamps.
- **Receipt-anchored verification.** `verify_authority_chain(receipt, grants)` decides
  authorization against a completed ARP receipt — after the fact, by any third party,
  with no policy-enforcement point in the loop. Multi-grant aggregation: AUTHORIZED iff
  every cited non-bind grant is SATISFIED (a lone INDETERMINATE blocks).
- **Sub-delegation with attenuation.** A child grant's scope must be a subset of its
  parent's (`check_attenuation`); any widening is `VIOLATED(attenuation_breach)`, bounded
  by `max_depth`.
- **Self-grant rejection.** `grantor_did == grantee_did` is `VIOLATED(self_grant)`,
  checked before signature. The deeper grantor-control case is a stated verifier
  obligation (SPEC §3.2, §5.4).
- **Minimal revocation.** A grantor-hosted signed list with a freshness bound
  (`StaticRevocationList`); stale or absent ⇒ `INDETERMINATE(revocation_unknown)`.
- **Conformance corpus.** 33 deterministic vectors under `vectors/dat/0.1/`, regenerable
  from `vectors/_generate.py` and replayed by `tests/`. CI runs them on 3.11 / 3.12 and
  asserts the corpus is reproducible.

### Reserved / deferred to 0.2
- `authorization_ceremony` (WebAuthn/passkey grantor binding), CEL scope predicates,
  and distributed/transparency-log revocation. (`dat:initial-bind` and the ARP-side
  `dat_grant_id` bridge ship in 0.1 — see Added above and SPEC §13.)
