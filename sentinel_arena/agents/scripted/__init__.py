"""Scripted, non-LLM baseline agents used as smoke tests and the bar to beat."""

from .blue import NoOpBlue, ScriptedBlue
from .red import ScriptedRed

__all__ = ["ScriptedRed", "ScriptedBlue", "NoOpBlue"]
