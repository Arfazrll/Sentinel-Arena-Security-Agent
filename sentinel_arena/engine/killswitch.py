"""Kill switch — one control that halts all agents instantly (brief §1.7).

A thread-safe flag the referee checks before every tick and every action. When
tripped, the engagement stops immediately and records why.
"""

from __future__ import annotations

import threading


class KillSwitch:
    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason = ""

    def trip(self, reason: str = "manual") -> None:
        self._reason = reason
        self._event.set()

    def wait(self, timeout: float) -> bool:
        """Sleep up to ``timeout`` seconds, waking at once if tripped.
        Returns True if the switch is (now) tripped."""
        return self._event.wait(timeout)

    @property
    def tripped(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason
