<!-- See CONTRIBUTING.md. Sign off every commit: git commit -s (DCO). -->

## What & why

<!-- What does this change, and why? Link any issue. -->

## Spec / vectors / code move together

- [ ] `SPEC.md` updated (or N/A — no behavioural change)
- [ ] Vectors regenerated (`python vectors/_generate.py`) and committed; `git diff vectors/` is clean
- [ ] New guarantee → happy-path vector; new rejection / `INDETERMINATE` reason → its own vector
- [ ] `CHANGELOG.md` updated

## Checks (ran locally)

- [ ] `python -m pytest -q` green
- [ ] examples run (`python examples/*.py`)
- [ ] `INDETERMINATE` is never collapsed into pass/fail
- [ ] No new crypto (identity/signing reused from `sm-arp`); core stays dependency-free

## Wire-impact

<!-- Does this change the DAT envelope or verification ordering? If so, describe the
     impact on existing grants/receipts. Envelope/ordering changes need an RFC-style
     SPEC PR first. -->
