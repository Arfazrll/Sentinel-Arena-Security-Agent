"""Exceptions raised by the authorization gate.

Every denial path raises one of these; the gate logs the denial to the
tamper-evident audit trail before raising.
"""

from __future__ import annotations


class AuthzError(Exception):
    """Base class for all authorization failures."""


class OwnershipNotProven(AuthzError):
    """Host ownership has not been cryptographically proven (or proof expired).

    Raised when an action is attempted against a host that has no valid,
    unexpired verification proof on record. This is the gate that keeps the
    target input inert until ownership is established.
    """


class VerificationFailed(AuthzError):
    """A verification attempt ran but the expected token was not observed."""


class OutOfScope(AuthzError):
    """The requested host/path falls outside the authorized scope."""


class Blocked(AuthzError):
    """The requested host is on the scope's hard blocklist.

    Blocklist always wins over any allow rule.
    """


class ScopeExpired(AuthzError):
    """The current time is outside the scope's authorized time window."""


class InvalidScope(AuthzError):
    """The scope itself is not well-formed or violates a safety constraint."""
