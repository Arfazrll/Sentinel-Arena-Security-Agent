"""Non-destructive detection checks.

Each check makes benign, in-scope requests through the :class:`GatedHttpClient`
and returns a :class:`Finding` if the weakness is present, else ``None``. No
check sends a harmful payload, writes data, or tries to take the target down —
detection is by observation only, against our own sandbox.

In a later milestone these become thin wrappers around mature OSS DAST tools;
the interface (``check(client) -> Finding | None``) stays the same.
"""

from __future__ import annotations

import uuid
from typing import Callable

from .client import GatedHttpClient, Response
from .findings import Finding, Severity

Check = Callable[[GatedHttpClient], "Finding | None"]


def _fid() -> str:
    return "F-" + uuid.uuid4().hex[:8]


def check_security_headers(client: GatedHttpClient) -> Finding | None:
    r = client.get("/")
    if r.status != 200:
        return None  # a blocked/4xx response proves nothing about header hygiene
    missing = [h for h in ("X-Content-Type-Options", "X-Frame-Options",
                           "Content-Security-Policy") if h not in r.headers]
    if missing:
        return Finding(
            id=_fid(), title="Missing security response headers", owasp="A05",
            severity=Severity.MEDIUM,
            description="Content pages are served without standard protective headers.",
            evidence=f"GET / is missing: {', '.join(missing)}",
            mitigation="Set X-Content-Type-Options, X-Frame-Options, and a CSP on "
                       "every response.",
            url=f"{client.base_url}/",
        )
    return None


def check_reflected_xss(client: GatedHttpClient) -> Finding | None:
    # Benign, unique marker — not an executable payload. We only check whether
    # our own input is reflected without encoding.
    marker = f"sentinel{uuid.uuid4().hex[:6]}marker"
    r = client.get(f"/search?q={marker}")
    if r.status == 200 and marker in r.text:
        return Finding(
            id=_fid(), title="Reflected input without output encoding", owasp="A03",
            severity=Severity.HIGH,
            description="User-supplied query input is reflected into the response "
                        "unchanged, indicating missing output encoding.",
            evidence=f"Marker {marker!r} reflected verbatim at /search.",
            mitigation="Apply context-aware output encoding to all user input; add "
                       "a strict Content-Security-Policy.",
            url=f"{client.base_url}/search",
        )
    return None


def check_exposed_admin(admin_path: str) -> Check:
    def _check(client: GatedHttpClient) -> Finding | None:
        r = client.get(admin_path)
        if r.status == 200 and "admin" in r.text.lower():
            return Finding(
                id=_fid(), title="Admin panel reachable without authentication",
                owasp="A01", severity=Severity.HIGH,
                description="An administrative interface is served without any "
                            "authentication or authorization check.",
                evidence=f"GET {admin_path} returned 200 with admin content.",
                mitigation="Require authentication and authorization on all admin "
                           "routes; never rely on an unguessable path.",
                url=f"{client.base_url}{admin_path}",
            )
        return None
    return _check


def check_verbose_errors(client: GatedHttpClient) -> Finding | None:
    r = client.get("/error")
    if "Traceback" in r.text or "File \"" in r.text:
        return Finding(
            id=_fid(), title="Verbose server errors leak stack traces", owasp="A05",
            severity=Severity.LOW,
            description="Server error responses include stack traces and internal "
                        "file paths.",
            evidence="GET /error returned a Python traceback in the body.",
            mitigation="Return generic error pages; log details server-side only.",
            url=f"{client.base_url}/error",
        )
    return None


def check_sensitive_file(client: GatedHttpClient) -> Finding | None:
    r = client.get("/config.json")
    if r.status == 200 and ("password" in r.text.lower() or "debug" in r.text.lower()):
        return Finding(
            id=_fid(), title="Sensitive config file exposed under web root",
            owasp="A05", severity=Severity.MEDIUM,
            description="A configuration file containing secrets is served from the "
                        "web root.",
            evidence="GET /config.json returned configuration including a credential.",
            mitigation="Remove secrets from the web root; deny access to config "
                       "files at the server.",
            url=f"{client.base_url}/config.json",
        )
    return None


def build_checks(admin_path: str) -> dict[str, Check]:
    """Return the detection suite keyed by the scenario's ``detect`` field."""
    return {
        "security_headers": check_security_headers,
        "reflected_xss": check_reflected_xss,
        "exposed_admin": check_exposed_admin(admin_path),
        "verbose_errors": check_verbose_errors,
        "sensitive_file": check_sensitive_file,
    }
