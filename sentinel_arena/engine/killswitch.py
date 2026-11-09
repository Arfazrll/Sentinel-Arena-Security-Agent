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

    @property
    def tripped(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason
