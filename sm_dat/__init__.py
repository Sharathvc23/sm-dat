"""sm-dat — Delegated Authority Token.

The principal-signed grant defining what an agent is allowed to do. The
"was it authorized?" half of agent accountability; companion to sm-arp's
"did it happen?". See SPEC.md.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _dist_version

from sm_arp import Identity  # re-export the shared identity primitive

# Derived from installed distribution metadata, never hand-maintained. A literal
# here is a second copy of pyproject's ``version`` with nothing comparing them —
# the shape that shipped sm-provision 0.1.0 reporting "0.0.1" and sm-authority
# 0.1.0 reporting the same wrong value from the same template. Correct today is
# not the test; it drifts at the next bump.
try:  # pragma: no cover - trivial branch, both sides asserted in tests
    __version__ = _dist_version("sm-dat")
except _PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0.dev0"

from .bridge import make_dat_verifier
from .grant import DAT_VERSION, build_grant, build_initial_bind, sign_grant, verify_grant_signature
from .ledger import LedgerContext
from .revocation import StaticRevocationList
from .verify import (
    INDETERMINATE,
    SATISFIED,
    VIOLATED,
    ChainTrace,
    GrantNode,
    Verdict,
    check_attenuation,
    verify_authority_chain,
    verify_authority_chain_trace,
    verify_grant,
)

__all__ = [
    "DAT_VERSION",
    "Identity",
    "build_grant",
    "build_initial_bind",
    "sign_grant",
    "verify_grant_signature",
    "verify_grant",
    "verify_authority_chain",
    "verify_authority_chain_trace",
    "GrantNode",
    "ChainTrace",
    "make_dat_verifier",
    "check_attenuation",
    "LedgerContext",
    "StaticRevocationList",
    "Verdict",
    "SATISFIED",
    "VIOLATED",
    "INDETERMINATE",
]
