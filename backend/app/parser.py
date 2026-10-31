"""Parse OpenSSH auth log lines (syslog or ISO timestamps) into structured events."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional

SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s")
ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

PATTERNS = [
    ("failed", re.compile(r"Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")),
    ("accepted", re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")),
    ("invalid", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")),
]


@dataclass(frozen=True)
class AuthEvent:
    ts: datetime
    kind: str  # failed | accepted | invalid
    user: str
    ip: str
    invalid_user: bool = False


def _parse_ts(line: str, year: int) -> Optional[datetime]:
    m = ISO_TS.match(line)
    if m:
        return datetime.strptime(m.group("ts"), "%Y-%m-%dT%H:%M:%S")
    m = SYSLOG_TS.match(line)
    if m:
        ts = re.sub(r"\s+", " ", m.group("ts"))
        return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
    return None


def parse_line(line: str, year: int = 2026) -> Optional[AuthEvent]:
    if "sshd" not in line:
        return None
    ts = _parse_ts(line, year)
    if ts is None:
        return None
    for kind, pat in PATTERNS:
        m = pat.search(line)
        if m:
            invalid = kind == "invalid" or bool(m.groupdict().get("invalid"))
            return AuthEvent(ts=ts, kind=kind, user=m.group("user") or "?", ip=m.group("ip"), invalid_user=invalid)
    return None


def parse_log(text: str | Iterable[str], year: int = 2026) -> List[AuthEvent]:
    lines = text.splitlines() if isinstance(text, str) else text
    events = []
    for line in lines:
        ev = parse_line(line.rstrip("\n"), year)
        if ev:
            events.append(ev)
    return events
