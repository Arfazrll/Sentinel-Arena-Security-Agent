"""The only way the platform makes an outbound request.

Every call passes through the authorization gate (ownership proof + scope) and a
rate limiter before a byte leaves. Out-of-scope or unauthorized requests raise
and are logged by the gate; they never reach the network. This is the chokepoint
that enforces safety invariants #1 and #4 at runtime.
"""

from __future__ import annotations

import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field

from ..authz import AuthorizationGate, Scope


class TargetUnreachable(Exception):
    """The target host gave no HTTP answer at all (DNS/connect/TLS/timeout).

    Distinct from an HTTP error status, which *is* an answer. The external
    scanner turns this into a clear "we couldn't reach your site" message rather
    than inventing findings from an empty response."""


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    text: str


class RateLimiter:
    """Sliding-window limiter derived from the scope's rate cap."""

    def __init__(self, max_requests: int, per_seconds: int) -> None:
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self._times: deque[float] = deque()

    def acquire(self) -> None:
        now = time.monotonic()
        while self._times and now - self._times[0] > self.per_seconds:
            self._times.popleft()
        if len(self._times) >= self.max_requests:
            sleep_for = self.per_seconds - (now - self._times[0])
            if sleep_for > 0:
                time.sleep(min(sleep_for, 0.5))  # bounded; keeps sims quick
            now = time.monotonic()
            while self._times and now - self._times[0] > self.per_seconds:
                self._times.popleft()
        self._times.append(time.monotonic())


@dataclass
class GatedHttpClient:
    gate: AuthorizationGate
    user_id: str
    host: str  # the authorized host, e.g. "127.0.0.1"
    base_url: str
    scope: Scope
    actor: str = "red"
    _limiter: RateLimiter = field(init=False)

    def __post_init__(self) -> None:
        self._limiter = RateLimiter(
            self.scope.rate_cap.max_requests, self.scope.rate_cap.per_seconds
        )

    def get(self, path: str, timeout: float = 3.0) -> Response:
        # 1. Authorization + scope — raises if not permitted (and logs the deny).
        self.gate.check(self.user_id, self.host, path.split("?", 1)[0], self.scope)
        # 2. Rate cap.
        self._limiter.acquire()
        # 3. The actual request, tagged with our actor identity.
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, headers={"X-Arena-Actor": self.actor})
        ctx = None
        if url.lower().startswith("https"):
            try:
                from ..config import ssl_context
                ctx = ssl_context()
            except Exception:
                ctx = None
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", "replace")
                return Response(status=resp.status, headers=dict(resp.headers),
                               text=body)
        except urllib.error.HTTPError as e:
            # A real HTTP response (4xx/5xx) is still an answer from the host.
            body = e.read().decode("utf-8", "replace") if e.fp else ""
            return Response(status=e.code, headers=dict(e.headers or {}), text=body)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # No HTTP answer at all: DNS/connect/TLS/timeout. Surface it clearly
            # so callers (e.g. the external scanner) can report "unreachable"
            # instead of hanging or 500-ing.
            reason = getattr(e, "reason", e)
            raise TargetUnreachable(
                f"could not connect to {self.host}: {reason}") from e
