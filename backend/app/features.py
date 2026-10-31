"""Aggregate auth events into per-source-IP behavioural features."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .parser import AuthEvent

FEATURES = [
    "failed_count",
    "unique_users",
    "invalid_user_count",
    "success_count",
    "fail_ratio",
    "attempts_per_min",
    "root_attempts",
]

# Features the classifier consumes. attempts_per_min is reported for analysts but
# excluded from the model: a fumbling human and a bot both look "fast" over a short
# span, and dropping it improved 5-fold CV AUC and fixed single-target brute force.
MODEL_FEATURES = [f for f in FEATURES if f != "attempts_per_min"]


def ip_features(events: List[AuthEvent]) -> Dict[str, Dict[str, float]]:
    by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
    for ev in events:
        by_ip[ev.ip].append(ev)

    out: Dict[str, Dict[str, float]] = {}
    for ip, evs in by_ip.items():
        failed = sum(1 for e in evs if e.kind == "failed")
        success = sum(1 for e in evs if e.kind == "accepted")
        # "Invalid user" lines usually precede a "Failed ... invalid user" line; count once.
        invalid = sum(1 for e in evs if e.kind == "failed" and e.invalid_user) or sum(
            1 for e in evs if e.kind == "invalid"
        )
        users = {e.user for e in evs}
        root = sum(1 for e in evs if e.user == "root" and e.kind == "failed")
        times = sorted(e.ts for e in evs)
        span_min = max((times[-1] - times[0]).total_seconds() / 60.0, 1.0)
        attempts = failed + success
        out[ip] = {
            "failed_count": float(failed),
            "unique_users": float(len(users)),
            "invalid_user_count": float(invalid),
            "success_count": float(success),
            "fail_ratio": failed / attempts if attempts else 0.0,
            "attempts_per_min": attempts / span_min,
            "root_attempts": float(root),
            "first_seen": times[0].isoformat(),
            "last_seen": times[-1].isoformat(),
        }
    return out
