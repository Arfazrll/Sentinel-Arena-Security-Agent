"""Telemetry: engagement event store + benign traffic generation."""

from .events import Event, EventStore, InMemoryEventSink

__all__ = ["Event", "EventStore", "InMemoryEventSink"]
