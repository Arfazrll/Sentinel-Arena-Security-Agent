"""The bundled vulnerable app — the self-deployed sandbox target.

An intentionally weak storefront, with benign, self-contained planted
weaknesses, served over plain HTTP on 127.0.0.1 only. It exists so the whole
engagement can run offline against a target we own, with no third party ever
involved. Nothing here reads the host filesystem or does anything destructive;
the "flag" is an in-memory planted secret.

Planted weaknesses (all detectable, none harmful):
  * Missing security headers on content pages        (A05)
  * Reflected, unencoded input at /search            (A03)
  * Admin panel with no authentication               (A01)
  * Verbose stack trace at /error                    (A05)
  * Sensitive config file at /config.json            (A05)

Discovery chain (so a scripted red team can actually reach the flag):
  GET /          -> HTML comment leaks the (randomized) admin path
  GET <admin>    -> unauthenticated; discloses the (randomized) flag path
  GET <flag>     -> returns the planted flag value to anyone

It also serves /.well-known/sentinel-arena.txt with the authorization token, so
the authorization gate verifies ownership of 127.0.0.1 *for real* — the gate is
exercised, never bypassed.

A blocked-actor set lets the blue team's ``block_ip`` action have a real,
observable effect: requests carrying a blocked ``X-Arena-Actor`` header get 403
(except /health, which always answers so service-liveness SLA is measured
separately from access control).
"""

from __future__ import annotations

import html
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
}

# Every planted weakness the sandbox knows how to serve, keyed by the same
# ``detect`` string a scenario uses. A scenario's weakness set selects which of
# these are actually present, so different scenarios yield genuinely different
# reports. The admin->flag discovery chain (info leak + admin + flag) is always
# served regardless, so every scenario stays solvable.
ALL_WEAKNESSES = {
    "security_headers",     # A05: content pages lack protective headers
    "reflected_xss",        # A03: input reflected without encoding
    "exposed_admin",        # A01: admin reachable without auth (chain; always on)
    "verbose_errors",       # A05: stack traces leaked on error
    "sensitive_file",       # A05: secret config under web root
    "insecure_cookie",      # A07: session cookie without HttpOnly/Secure
    "cors_wildcard",        # A05: Access-Control-Allow-Origin: *
    "version_disclosure",   # A06: outdated component advertised in a header
    "directory_listing",    # A05: directory index exposed
}


@dataclass
class AppConfig:
    token: str
    flag_path: str
    admin_path: str
    flag_value: str
    credential: str
    # Which planted weaknesses this instance serves. Defaults to all of them so
    # a directly-constructed app (tests, ad-hoc use) is maximally vulnerable; the
    # range passes a scenario-specific subset.
    weaknesses: set[str] = field(default_factory=lambda: set(ALL_WEAKNESSES))
    blocked_actors: set[str] = field(default_factory=set)
    sink: object = None  # InMemoryEventSink | None
    tick_provider: object = None  # callable -> int, optional
    # Control-plane token. When set (containerized range), the host can toggle
    # the blocklist over an internal, token-gated endpoint. None = endpoint
    # does not exist at all (the default, in-process path mutates the set
    # directly instead).
    control_token: str | None = None

    def current_tick(self) -> int:
        try:
            return int(self.tick_provider()) if callable(self.tick_provider) else -1
        except Exception:
            return -1


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, config: AppConfig):
        super().__init__(addr, handler)
        self.config = config


class _Handler(BaseHTTPRequestHandler):
    server_version = "CornerShop/1.0"

    # --- plumbing --------------------------------------------------------
    def log_message(self, *args):  # silence default stderr logging
        return

    @property
    def cfg(self) -> AppConfig:
        return self.server.config  # type: ignore[attr-defined]

    def _actor(self) -> str:
        return self.headers.get("X-Arena-Actor", "anonymous")

    def _has(self, key: str) -> bool:
        return key in self.cfg.weaknesses

    def _record(self, status: int, marker: str = "") -> None:
        sink = self.cfg.sink
        if sink is not None:
            sink.record_request(
                actor=self._actor(), method=self.command, path=self.path,
                status=status, marker=marker, tick=self.cfg.current_tick(),
            )

    def _send(self, status: int, body: str, *, secure: bool = False,
              content_type: str = "text/html; charset=utf-8", marker: str = "",
              extra_headers: dict[str, str] | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if secure:
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self._record(status, marker)

    # --- routing ---------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        actor = self._actor()

        # Control plane (only exists when a control token is configured). Used
        # by the Docker-backed range to toggle the blocklist from the host. It
        # is token-gated, not recorded as range traffic, and never part of a
        # scenario's scope.
        if self.cfg.control_token and path.startswith("/__arena/"):
            return self._handle_control(parsed)

        # Health always answers (service-liveness SLA), even for blocked actors.
        if path == "/health":
            return self._send(200, "ok", secure=True, content_type="text/plain")

        # Blocked actors are refused everywhere else (blue's block_ip at work).
        if actor in self.cfg.blocked_actors:
            return self._send(403, "Forbidden", content_type="text/plain",
                             marker="blocked")

        if path == "/.well-known/sentinel-arena.txt":
            return self._send(200, self.cfg.token, secure=True,
                             content_type="text/plain")

        if path == "/":
            # Planted info leak: an HTML comment discloses the admin path. This
            # is the first link of the discovery chain, so it is always present.
            body = (
                "<!doctype html><html><head><title>Corner Shop</title></head>"
                "<body><h1>Corner Shop</h1><p>Fresh deals daily.</p>"
                f"<!-- staff: admin console at {self.cfg.admin_path} -->"
                "</body></html>"
            )
            extra: dict[str, str] = {}
            if self._has("insecure_cookie"):
                # Planted A07: session cookie without HttpOnly/Secure/SameSite.
                extra["Set-Cookie"] = f"sa_session={self.cfg.credential}; Path=/"
            if self._has("version_disclosure"):
                # Planted A06: advertises a specific, outdated component version.
                extra["X-Powered-By"] = "Express/4.17.1"
            # secure headers present only when "security_headers" is NOT a
            # planted weakness for this scenario.
            return self._send(200, body, secure=not self._has("security_headers"),
                             extra_headers=extra or None)

        if path == "/search":
            q = parse_qs(parsed.query).get("q", [""])[0]
            if self._has("reflected_xss"):
                # Planted A03: input echoed without output encoding.
                body = f"<html><body>Results for: {q}</body></html>"
            else:
                body = f"<html><body>Results for: {html.escape(q)}</body></html>"
            return self._send(200, body, marker="reflected")

        if path == "/api/products":
            # A benign JSON endpoint. Planted A05 when CORS is wide open.
            extra = {}
            if self._has("cors_wildcard"):
                extra["Access-Control-Allow-Origin"] = "*"
            return self._send(200, '[{"id":1,"name":"Coffee"},{"id":2,"name":"Tea"}]',
                             content_type="application/json",
                             extra_headers=extra or None)

        if path.rstrip("/") == "/uploads" and self._has("directory_listing"):
            # Planted A05: directory index exposed under the web root.
            body = ("<html><head><title>Index of /uploads</title></head><body>"
                    "<h1>Index of /uploads</h1><ul>"
                    "<li><a href='invoice-2023.pdf'>invoice-2023.pdf</a></li>"
                    "<li><a href='backup.zip'>backup.zip</a></li></ul></body></html>")
            return self._send(200, body)

        if path == self.cfg.admin_path:
            # Planted broken access control: no auth; discloses the flag path.
            body = (
                "<html><body><h1>Admin Console</h1>"
                f"<p>Backups: <a href='{self.cfg.flag_path}'>archive</a></p>"
                "</body></html>"
            )
            return self._send(200, body, marker="admin")

        if path == self.cfg.flag_path:
            # Planted sensitive data exposure: the flag, to anyone.
            return self._send(200, self.cfg.flag_value, content_type="text/plain",
                             marker="flag")

        if path == "/config.json" and self._has("sensitive_file"):
            # Planted sensitive file under web root.
            body = (
                '{"app":"corner-shop","debug":true,'
                f'"db_password":"{self.cfg.credential}"}}'
            )
            return self._send(200, body, content_type="application/json",
                             marker="sensitive")

        if path == "/error":
            if self._has("verbose_errors"):
                # Planted A05: verbose error with a (fake) stack trace.
                body = (
                    "<html><body><h2>500 Internal Server Error</h2><pre>"
                    "Traceback (most recent call last):\n"
                    '  File "/srv/app/handlers.py", line 42, in checkout\n'
                    "    total = cart.total()\n"
                    "AttributeError: 'NoneType' object has no attribute 'total'\n"
                    "</pre></body></html>"
                )
            else:
                body = ("<html><body><h2>500 Internal Server Error</h2>"
                        "<p>Something went wrong. Please try again later.</p></body></html>")
            return self._send(500, body, marker="verbose_error")

        return self._send(404, "Not Found", content_type="text/plain")

    def do_HEAD(self):
        return self.do_GET()

    def _handle_control(self, parsed) -> None:
        # Requires the shared control token; bypasses the request sink entirely.
        if self.headers.get("X-Arena-Control") != self.cfg.control_token:
            self.send_response(403)
            self.end_headers()
            return
        actor = parse_qs(parsed.query).get("actor", [""])[0]
        if parsed.path == "/__arena/block" and actor:
            self.cfg.blocked_actors.add(actor)
        elif parsed.path == "/__arena/unblock" and actor:
            self.cfg.blocked_actors.discard(actor)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


def start_app(config: AppConfig, host: str = "127.0.0.1", port: int = 0):
    """Start the app in a background thread. Returns (server, base_url, thread)."""
    server = _Server((host, port), _Handler, config)
    actual_port = server.server_address[1]
    base_url = f"http://{host}:{actual_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, base_url, thread
