"""sm-dat — Delegated Authority Token.

The principal-signed grant defining what an agent is allowed to do. The
"was it authorized?" half of agent accountability; companion to sm-arp's
"did it happen?". See SPEC.md.
"""

from __future__ import annotations

from sm_arp import Identity  # re-export the shared identity primitive

__version__ = "0.1.0"  # keep in lockstep with pyproject.toml `version`

from .bridge import make_dat_verifier
from .grant import DAT_VERSION, build_grant, build_initial_bind, sign_grant, verify_grant_signature
from .ledger import LedgerContext
from .revocation import StaticRevocationList
from .verify import (
    INDETERMINATE,
    SATISFIED,
    VIOLATED,
    Verdict,
    check_attenuation,
    verify_authority_chain,
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
    "make_dat_verifier",
    "check_attenuation",
    "LedgerContext",
    "StaticRevocationList",
    "Verdict",
    "SATISFIED",
    "VIOLATED",
    "INDETERMINATE",
]
