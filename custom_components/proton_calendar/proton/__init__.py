"""Self-contained Proton Calendar client (SRP login, OpenPGP decryption, iCal expansion)."""

from .client import (
    HumanVerificationFailed,
    HumanVerificationRequired,
    InvalidCredentials,
    InvalidMailboxPassword,
    InvalidTwoFactorCode,
    LoginResult,
    ProtonApiError,
    ProtonAuthError,
    ProtonCalendar,
    ProtonClient,
    ProtonConnectionError,
    ProtonError,
    Session,
    UnsupportedTwoFactor,
)
from .events import EventCards, Occurrence, expand_events

__all__ = [
    "EventCards",
    "HumanVerificationFailed",
    "HumanVerificationRequired",
    "InvalidCredentials",
    "InvalidMailboxPassword",
    "InvalidTwoFactorCode",
    "LoginResult",
    "Occurrence",
    "ProtonApiError",
    "ProtonAuthError",
    "ProtonCalendar",
    "ProtonClient",
    "ProtonConnectionError",
    "ProtonError",
    "Session",
    "UnsupportedTwoFactor",
    "expand_events",
]
