from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator

class NormalizedEvent(BaseModel):
    """ECS-inspired event envelope. Raw source payload is retained without mutation."""
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_type: str
    event_kind: str = "event"
    event_category: list[str] = Field(default_factory=list)
    event_type: list[str] = Field(default_factory=list)
    event_action: str | None = None
    host_name: str | None = None
    user_name: str | None = None
    process_name: str | None = None
    process_command_line: str | None = None
    process_parent_name: str | None = None
    process_parent_command_line: str | None = None
    process_pid: int | None = None
    process_parent_pid: int | None = None
    event_id_code: int | str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    network_protocol: str | None = None
    file_path: str | None = None
    outcome: str | None = None
    severity: str = "info"
    tags: list[str] = Field(default_factory=list)
    raw_event: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, value):
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
