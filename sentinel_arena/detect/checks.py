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
    from urllib.parse import quote

    # Benign probe: a unique token wrapped in angle brackets. It is NOT an
    # executable payload (no script, no handler) — it only lets us tell raw
    # reflection (the token comes back with its literal "<") from correct output
    # encoding (the "<" comes back as "&lt;"). Alphanumeric-only markers can't
    # make that distinction, since encoding leaves them unchanged.
    token = uuid.uuid4().hex[:6]
    marker = f"<saxss{token}>"
    r = client.get(f"/search?q={quote(marker)}")
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


def _header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup (servers vary header casing)."""
    low = name.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return None


def check_insecure_cookie(client: GatedHttpClient) -> Finding | None:
    r = client.get("/")
    cookie = _header(r.headers, "Set-Cookie")
    if cookie and "httponly" not in cookie.lower():
        return Finding(
            id=_fid(), title="Session cookie set without HttpOnly/Secure flags",
            owasp="A07", severity=Severity.MEDIUM,
            description="A session cookie is issued without the HttpOnly and "
                        "Secure attributes, exposing it to theft via script or "
                        "plaintext transport.",
            evidence=f"Set-Cookie on / lacks HttpOnly: {cookie!r}",
            mitigation="Set HttpOnly, Secure and SameSite on all session cookies.",
            url=f"{client.base_url}/",
        )
    return None


def check_cors_wildcard(client: GatedHttpClient) -> Finding | None:
    r = client.get("/api/products")
    if _header(r.headers, "Access-Control-Allow-Origin") == "*":
        return Finding(
            id=_fid(), title="Permissive CORS policy (Access-Control-Allow-Origin: *)",
            owasp="A05", severity=Severity.MEDIUM,
            description="An API responds with a wildcard CORS origin, allowing any "
                        "website to read its responses in a user's browser.",
            evidence="GET /api/products returned Access-Control-Allow-Origin: *.",
            mitigation="Reflect only an explicit allowlist of trusted origins; "
                       "never pair a wildcard origin with credentials.",
            url=f"{client.base_url}/api/products",
        )
    return None


def check_version_disclosure(client: GatedHttpClient) -> Finding | None:
    r = client.get("/")
    powered = _header(r.headers, "X-Powered-By")
    if powered:
        return Finding(
            id=_fid(), title="Technology and version disclosed in response headers",
            owasp="A06", severity=Severity.LOW,
            description="A response header advertises a specific component and "
                        "version, helping an attacker match it to known CVEs.",
            evidence=f"X-Powered-By header present: {powered!r}.",
            mitigation="Suppress version banners (X-Powered-By, Server) and track "
                       "component versions for known-vulnerability alerts.",
            url=f"{client.base_url}/",
        )
    return None


def check_directory_listing(client: GatedHttpClient) -> Finding | None:
    r = client.get("/uploads/")
    if r.status == 200 and "index of" in r.text.lower():
        return Finding(
            id=_fid(), title="Directory listing exposed under the web root",
            owasp="A05", severity=Severity.MEDIUM,
            description="A directory returns an auto-generated index, exposing "
                        "file names (and often backups or archives) to anyone.",
            evidence="GET /uploads/ returned a directory index.",
            mitigation="Disable directory indexing; serve only explicit files.",
            url=f"{client.base_url}/uploads/",
        )
    return None


def build_checks(admin_path: str) -> dict[str, Check]:
    """Return the detection suite keyed by the scenario's ``detect`` field.

    Every check is observation-only and self-gating: it returns ``None`` when the
    target does not exhibit the weakness, so running the full suite against any
    scenario is safe and only surfaces what is actually present."""
    return {
        "security_headers": check_security_headers,
        "reflected_xss": check_reflected_xss,
        "exposed_admin": check_exposed_admin(admin_path),
        "verbose_errors": check_verbose_errors,
        "sensitive_file": check_sensitive_file,
        "insecure_cookie": check_insecure_cookie,
        "cors_wildcard": check_cors_wildcard,
        "version_disclosure": check_version_disclosure,
        "directory_listing": check_directory_listing,
    }
