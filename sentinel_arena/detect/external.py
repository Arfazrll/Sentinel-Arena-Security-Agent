"""Observation-only posture checks for a *verified external* host.

This is the safe, honest realization of "paste your site and find its
weaknesses". It is deliberately minimal and passive:

* it runs **only** against a host whose ownership has been proven to the gate;
* it makes a single ``GET /`` through the gated client (ownership proof + scope +
  rate limit enforced on that request) and derives every finding from the
  **response headers** — the same thing a tool like securityheaders.com inspects;
* it sends **no payload**, fuzzes **no paths**, and never runs the red/blue arena
  (that stays sandbox-only, where flags and a control plane exist).

So it cannot damage, overload, or "attack" the target; it observes how the site
already presents itself. New header checks go here; the richer path-based checks
in ``checks.py`` remain for the bundled sandbox range.
"""

from __future__ import annotations

from .checks import _fid, _header
from .client import GatedHttpClient, Response
from .findings import Finding, Severity


def _f(title: str, owasp: str, sev: Severity, desc: str, evidence: str,
       mitigation: str, url: str) -> Finding:
    return Finding(id=_fid(), title=title, owasp=owasp, severity=sev,
                   description=desc, evidence=evidence, mitigation=mitigation, url=url)


def analyze_headers(resp: Response, base_url: str) -> list[Finding]:
    """Derive observation-only findings from one root response's headers."""
    h = resp.headers
    out: list[Finding] = []

    missing = [n for n in ("X-Content-Type-Options", "X-Frame-Options",
                           "Content-Security-Policy") if _header(h, n) is None]
    if missing:
        out.append(_f(
            "Missing security response headers", "A05", Severity.MEDIUM,
            "The site is served without one or more standard protective headers.",
            f"GET / is missing: {', '.join(missing)}.",
            "Set X-Content-Type-Options, X-Frame-Options and a Content-Security-"
            "Policy on every response.", f"{base_url}/"))

    if _header(h, "Strict-Transport-Security") is None:
        out.append(_f(
            "HSTS not enabled (Strict-Transport-Security missing)", "A05",
            Severity.MEDIUM,
            "Without HSTS a browser can be downgraded to plaintext HTTP on the "
            "first or a tampered connection.",
            "GET / response has no Strict-Transport-Security header.",
            "Send Strict-Transport-Security with a long max-age (and preload once "
            "confident).", f"{base_url}/"))

    cookie = _header(h, "Set-Cookie")
    if cookie and "httponly" not in cookie.lower():
        out.append(_f(
            "Session cookie set without HttpOnly/Secure flags", "A07",
            Severity.MEDIUM,
            "A cookie is issued without HttpOnly/Secure, exposing it to script "
            "theft or plaintext transport.",
            f"Set-Cookie lacks HttpOnly: {cookie!r}.",
            "Set HttpOnly, Secure and SameSite on all session cookies.",
            f"{base_url}/"))

    if _header(h, "Access-Control-Allow-Origin") == "*":
        out.append(_f(
            "Permissive CORS policy (Access-Control-Allow-Origin: *)", "A05",
            Severity.MEDIUM,
            "A wildcard CORS origin lets any website read responses in a user's "
            "browser.",
            "Response carries Access-Control-Allow-Origin: *.",
            "Reflect only an explicit allowlist of trusted origins; never pair a "
            "wildcard with credentials.", f"{base_url}/"))

    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        val = _header(h, name)
        if val:
            out.append(_f(
                "Technology and version disclosed in response headers", "A06",
                Severity.LOW,
                "A response header advertises a component/version, helping an "
                "attacker match known CVEs.",
                f"{name} header present: {val!r}.",
                "Suppress version banners (X-Powered-By, Server) and monitor "
                "component versions for known-vulnerability alerts.", f"{base_url}/"))
            break

    if _header(h, "Referrer-Policy") is None:
        out.append(_f(
            "Referrer-Policy not set", "A05", Severity.LOW,
            "Without a Referrer-Policy, full URLs (possibly with tokens) can leak "
            "to third parties via the Referer header.",
            "GET / response has no Referrer-Policy header.",
            "Set Referrer-Policy (e.g. strict-origin-when-cross-origin).",
            f"{base_url}/"))

    return out


def scan_external_headers(client: GatedHttpClient, timeout: float = 20.0) -> list[Finding]:
    """One gated ``GET /`` -> all header findings. The client's gate enforces the
    ownership proof, scope and rate cap before the request leaves. Raises
    :class:`TargetUnreachable` (from the client) if the host gives no answer."""
    resp = client.get("/", timeout=timeout)
    return analyze_headers(resp, client.base_url)
