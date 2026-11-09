"""Non-destructive detection: gated outbound client, checks, and findings."""

from .client import GatedHttpClient, RateLimiter, Response
from .findings import OWASP_TOP_10, Finding, FindingList, Severity
from .checks import build_checks

__all__ = [
    "GatedHttpClient",
    "RateLimiter",
    "Response",
    "OWASP_TOP_10",
    "Finding",
    "FindingList",
    "Severity",
    "build_checks",
]
