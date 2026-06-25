# Governance

## Scope

| In scope | Out of scope |
| --- | --- |
| the Delegated Authority Token envelope + the verification decision procedure (the three-valued verdict, stateless/stateful constraints, attenuation, the receipt-anchored authority-chain check) | identity (`did:key`/`sm_arp`), the receipt format (Agency Receipt Protocol, ARP), reputation (Verifiable Receipts Profile + PARC), synchronous human approval (`sm-oversight`), the agent's plugin sandbox (`sm-airlock`), regulatory compliance (`sm-locp`), and grantor-to-human binding (a caller obligation, SPEC §5.4) |

The primitive owns one thing — answering *"did the principal permit this action?"* against
a signed grant. Anything outside the table belongs to a companion package or the caller.

## Versioning

Semantic Versioning 2.0.0. The DAT envelope and the verification ordering are frozen
within a major; a change requires an RFC-style PR to `SPEC.md` before code. `dat/0.1` is
published parallel to ARP v0.2; `dat/1.0` and ARP v1.0 in lockstep.

## Conformance

The vector corpus under `vectors/dat/0.1/` and the test suite under `tests/` are the
authoritative behavioural specification. A change in behaviour without a corresponding
vector/test change is a bug. Every guarantee in the README has a happy-path vector; every
rejection and every INDETERMINATE stage has its own — the negative and INDETERMINATE cases
are the point, because that is where an over-eager verifier silently grants authority it
cannot justify. The corpus is deterministic and regenerable (`vectors/_generate.py`); CI
fails if it drifts.

## Contributions

- PRs must include vectors/tests and pass `ruff` + `mypy --strict` + `pytest`.
- No expansion of the envelope or verification surface without an accepted RFC.
- INDETERMINATE must never be collapsed into a pass or a fail by the library.
- No domain-specific or deployment-specific content — this is a generic primitive.
- Sign off with the Developer Certificate of Origin (DCO).

## Attribution

Composes `sm-arp` (ARP receipts, VRP, and the shared Ed25519/JCS signing path). The
mirror relationship — receipt (*did it happen?*) ↔ grant (*was it allowed?*) — is why DAT
is a separate primitive rather than a field inside ARP.

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
