"""Explainable, time-bounded entity correlation for lab incident grouping."""
from __future__ import annotations
import ipaddress
from typing import Any

def _is_internal_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private and not address.is_loopback and not address.is_link_local and not address.is_reserved

def entity_keys(event: dict[str, Any]) -> dict[str, str]:
    """Produce conservative keys; public IPs and unscoped usernames are excluded."""
    keys: dict[str, str] = {}
    host, user = event.get("host_name"), event.get("user_name")
    if host:
        keys["host"] = f"host:{host.casefold()}"
    if user and ("\\" in user or "@" in user):
        keys["identity"] = f"identity:{user.casefold()}"
    if host and user:
        keys["host_user"] = f"host_user:{host.casefold()}:{user.casefold()}"
    if host:
        for field in ("process_pid", "process_parent_pid"):
            pid = event.get(field)
            if pid is not None:
                keys[f"process_pid:{host.casefold()}:{pid}"] = f"process_pid:{host.casefold()}:{pid}"
    for field in ("source_ip", "destination_ip"):
        value = event.get(field)
        if _is_internal_address(value):
            keys[f"private_ip:{value}"] = f"private_ip:{value}"
    return keys

def _weight(key: str) -> int:
    if key == "host": return 3
    if key == "host_user": return 4
    if key == "identity": return 3
    if key.startswith("process_pid:"): return 5
    if key.startswith("private_ip:"): return 4
    return 0

def score_entities(left: dict[str, str], right: dict[str, str]) -> tuple[int, list[str]]:
    matched = sorted(key for key in left.keys() & right.keys() if left[key] == right[key] and _weight(key))
    return sum(_weight(key) for key in matched), matched
