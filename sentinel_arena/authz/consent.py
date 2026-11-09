"""Immutable consent records.

One record per engagement authorization: who authorized, the exact scope they
authorized, when, and the verification result that backed it. Frozen so a
record cannot be mutated after the fact — it is evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from .scope import Scope
from .verification import VerificationMethod


class ConsentRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    scope: Scope
    method: VerificationMethod
    verified_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    note: str = ""

    def scope_fingerprint(self) -> str:
        return self.scope.fingerprint()
