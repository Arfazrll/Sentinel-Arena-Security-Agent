"""Sentinel Arena — authorized multi-agent security-resilience platform.

Safety invariant: no component may act against a target host until the
authorization gate (``sentinel_arena.authz``) has verified ownership of that
exact host and the action falls within the authorized scope.
"""

__version__ = "0.0.1"
