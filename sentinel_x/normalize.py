from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from .schema import NormalizedEvent

def normalize(payload: dict[str, Any], source_type: str | None = None) -> NormalizedEvent:
    source = (source_type or payload.get("source_type") or payload.get("source") or "synthetic").lower()
    ts = payload.get("timestamp") or payload.get("@timestamp") or payload.get("ts") or datetime.now(timezone.utc).isoformat()
    return NormalizedEvent(
        event_id=str(payload.get("event_id") or payload.get("id") or uuid4()),
        timestamp=ts, source_type=source,
        event_kind=payload.get("event_kind", "event"),
        event_category=payload.get("event_category", payload.get("category", [])),
        event_type=payload.get("event_type", payload.get("type", [])),
        event_action=payload.get("event_action", payload.get("action", payload.get("EventType"))),
        host_name=payload.get("host_name") or payload.get("hostname") or payload.get("Computer") or payload.get("host"),
        user_name=payload.get("user_name") or payload.get("user") or payload.get("User"),
        process_name=payload.get("process_name") or payload.get("Image") or payload.get("process"),
        process_command_line=payload.get("process_command_line") or payload.get("CommandLine") or payload.get("cmdline"),
        process_parent_name=payload.get("process_parent_name") or payload.get("ParentImage") or payload.get("parent_process"),
        process_parent_command_line=payload.get("process_parent_command_line") or payload.get("ParentCommandLine"),
        process_pid=payload.get("process_pid") or payload.get("ProcessId") or payload.get("pid"),
        process_parent_pid=payload.get("process_parent_pid") or payload.get("ParentProcessId") or payload.get("ppid"),
        event_id_code=payload.get("event_id_code") or payload.get("EventID"),
        source_ip=payload.get("source_ip") or payload.get("id.orig_h") or payload.get("src_ip") or payload.get("src"),
        destination_ip=payload.get("destination_ip") or payload.get("id.resp_h") or payload.get("dest_ip") or payload.get("dst"),
        source_port=payload.get("source_port") or payload.get("id.orig_p") or payload.get("src_port"),
        destination_port=payload.get("destination_port") or payload.get("id.resp_p") or payload.get("dest_port") or payload.get("dst_port"),
        network_protocol=payload.get("network_protocol") or payload.get("proto"),
        file_path=payload.get("file_path") or payload.get("TargetFilename") or payload.get("path"),
        outcome=payload.get("outcome") or payload.get("result"),
        severity=payload.get("severity", "info"),
        tags=payload.get("tags", []), raw_event=payload.get("raw_event", payload),
    )
