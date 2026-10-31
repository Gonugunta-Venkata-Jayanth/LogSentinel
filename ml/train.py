"""Generate a labelled synthetic SSH auth-log corpus, train a classifier, export it.

    python ml/train.py            # writes backend/app/model.json, frontend/model.json,
                                  # samples/auth.log and ml/metrics.json

The corpus simulates four behaviours seen on any internet-facing Linux box:
  * legit      - real users, mostly successful logins, the odd typo
  * forgetful  - real user fumbling a password several times (hard negative)
  * bruteforce - one IP hammering root/admin at high rate
  * stuffing   - one IP trying many usernames (mostly invalid) slowly
  * lowslow    - patient attacker, few attempts spread over hours
Logs are rendered as real OpenSSH lines and pushed through the same parser and
feature code the API uses, so training and serving can never drift apart.
"""
from __future__ import annotations

import json
import math
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.features import MODEL_FEATURES as FEATURES  # noqa: E402
from app.features import ip_features  # noqa: E402
from app.parser import parse_log  # noqa: E402

LOG_FEATURES = ["failed_count", "unique_users", "invalid_user_count", "success_count", "root_attempts"]
REAL_USERS = ["jay", "deploy", "ubuntu", "ci", "anita", "ravi"]
DICT_USERS = ["admin", "test", "oracle", "postgres", "guest", "user", "ftp", "pi", "git", "support", "ubnt", "mysql"]


def ts(t: datetime) -> str:
    # syslog pads single-digit days with a space ("Oct  5"), which the parser accepts
    return f"{t.strftime('%b')} {t.day:>2} {t.strftime('%H:%M:%S')}"


def line(t, pid, msg):
    return f"{ts(t)} web-01 sshd[{pid}]: {msg}"


def rand_ip(rng, private=False):
    if private:
        return f"10.0.{rng.randint(0, 20)}.{rng.randint(2, 250)}"
    return f"{rng.randint(23, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def session(rng, kind, start):
    ip = rand_ip(rng, private=(kind == "legit" and rng.random() < 0.6))
    out, t = [], start
    pid = rng.randint(1000, 60000)

    def fail(user, invalid):
        nonlocal t, pid
        pid += 1
        port = rng.randint(30000, 65000)
        if invalid:
            out.append(line(t, pid, f"Invalid user {user} from {ip} port {port}"))
            out.append(line(t, pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2"))
        else:
            out.append(line(t, pid, f"Failed password for {user} from {ip} port {port} ssh2"))

    def ok(user):
        nonlocal pid
        pid += 1
        method = rng.choice(["publickey", "publickey", "password"])
        out.append(line(t, pid, f"Accepted {method} for {user} from {ip} port {rng.randint(30000, 65000)} ssh2"))

    if kind == "legit":
        user = rng.choice(REAL_USERS)
        for _ in range(rng.randint(1, 6)):
            if rng.random() < 0.15:
                fail(user, False)
                t += timedelta(seconds=rng.randint(3, 20))
            ok(user)
            t += timedelta(minutes=rng.randint(20, 240))
    elif kind == "forgetful":  # legit user fumbling a password - hard negative
        user = rng.choice(REAL_USERS + ["root"])
        for _ in range(rng.randint(2, 7)):
            fail(user, False)
            t += timedelta(seconds=rng.uniform(4, 40))
        if rng.random() < 0.8:
            ok(user)
    elif kind == "bruteforce":
        targets = ["root"] if rng.random() < 0.4 else ["root", "root", "admin", "ubuntu"]
        for _ in range(rng.randint(15, 300)):
            fail(rng.choice(targets), False)
            t += timedelta(seconds=rng.uniform(0.3, 4))
    elif kind == "stuffing":
        for _ in range(rng.randint(10, 80)):
            u = rng.choice(DICT_USERS + REAL_USERS)
            fail(u, u not in REAL_USERS)
            t += timedelta(seconds=rng.uniform(5, 60))
        if rng.random() < 0.1:  # occasionally a stuffed credential works - the scary case
            ok(rng.choice(REAL_USERS))
    elif kind == "lowslow":
        for _ in range(rng.randint(2, 12)):
            fail(rng.choice(["root"] + DICT_USERS[:4] + REAL_USERS[:2]), rng.random() < 0.4)
            t += timedelta(minutes=rng.uniform(10, 90))
    return ip, out


def build_corpus(n=1600, seed=7, label_noise=0.03):
    rng = random.Random(seed)
    base = datetime(2026, 10, 1)
    sessions, labels = [], []
    for _ in range(n):
        kind = rng.choices(["legit", "forgetful", "bruteforce", "stuffing", "lowslow"], [0.45, 0.12, 0.16, 0.13, 0.14])[0]
        start = base + timedelta(minutes=rng.randint(0, 60 * 24 * 25))
        ip, lines = session(rng, kind, start)
        sessions.append(lines)
        label = 0 if kind in ("legit", "forgetful") else 1
        if rng.random() < label_noise:  # imperfect analyst labels, as in real SOC data
            label = 1 - label
        labels.append(label)
    return sessions, labels


def to_matrix(sessions):
    rows = []
    for lines in sessions:
        feats = ip_features(parse_log(lines))
        f = next(iter(feats.values()))
        rows.append([math.log1p(f[k]) if k in LOG_FEATURES else f[k] for k in FEATURES])
    return np.array(rows)


def main():
    sessions, y = build_corpus()
    X = to_matrix(sessions)
    y = np.array(y)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=0, stratify=y)
    scaler = StandardScaler().fit(Xtr)
    clf = LogisticRegression(max_iter=1000, C=0.3).fit(scaler.transform(Xtr), ytr)
    proba = clf.predict_proba(scaler.transform(Xte))[:, 1]
    auc = roc_auc_score(yte, proba)
    report = classification_report(yte, proba >= 0.5, output_dict=True)
    print(f"ROC-AUC={auc:.4f}  precision={report['1']['precision']:.3f}  recall={report['1']['recall']:.3f}")

    spec = {
        "version": "2026.10.31",
        "type": "logistic_regression",
        "features": FEATURES,
        "log_features": LOG_FEATURES,
        "mean": scaler.mean_.round(6).tolist(),
        "scale": scaler.scale_.round(6).tolist(),
        "coef": clf.coef_[0].round(6).tolist(),
        "intercept": round(float(clf.intercept_[0]), 6),
        "threshold": 0.5,
        "metrics": {"roc_auc": round(auc, 4), "precision": round(report["1"]["precision"], 4),
                    "recall": round(report["1"]["recall"], 4), "test_size": int(len(yte))},
    }
    for p in (ROOT / "backend/app/model.json", ROOT / "frontend/model.json"):
        p.write_text(json.dumps(spec, indent=2))
    (ROOT / "ml/metrics.json").write_text(json.dumps(spec["metrics"], indent=2))

    # A realistic demo log: ~40 sessions interleaved by time.
    rng = random.Random(42)
    demo = []
    for kind in ["legit"] * 20 + ["forgetful"] * 3 + ["bruteforce"] * 4 + ["stuffing"] * 3 + ["lowslow"] * 3:
        _, lines = session(rng, kind, datetime(2026, 10, 30, rng.randint(0, 11), rng.randint(0, 59)))
        demo.extend(lines)
    demo.sort(key=lambda s: s[:15])
    (ROOT / "samples/auth.log").write_text("\n".join(demo) + "\n")
    (ROOT / "frontend/sample.log").write_text("\n".join(demo) + "\n")

    # Golden scores for the JS parity test (frontend/tests/engine.test.mjs).
    from app.main import analyze_text  # imported late so it loads the model just written

    golden = {r["ip"]: [r["score"], r["verdict"]] for r in analyze_text("\n".join(demo))["results"]}
    (ROOT / "samples/expected_scores.json").write_text(json.dumps(golden, indent=1))
    return spec


if __name__ == "__main__":
    main()
