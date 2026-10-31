"""LogSentinel API: score SSH auth logs for brute-force / credential-stuffing behaviour."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .features import ip_features
from .model import ThreatModel
from .parser import parse_log
from .storage import archive_raw_log, make_store

app = FastAPI(title="LogSentinel", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL = ThreatModel.load()
STORE = make_store()
MAX_LOG_BYTES = int(os.getenv("MAX_LOG_BYTES", str(2_000_000)))


class AnalyzeRequest(BaseModel):
    log: str = Field(..., description="Raw auth.log / journalctl text")
    year: int = 2026
    save: bool = True
    host: str = "unknown"


def analyze_text(text: str, year: int = 2026) -> dict:
    events = parse_log(text, year)
    feats = ip_features(events)
    results = []
    for ip, f in feats.items():
        p = MODEL.score(f)
        results.append({"ip": ip, "score": round(p, 4), "verdict": MODEL.verdict(p), **f})
    results.sort(key=lambda r: r["score"], reverse=True)
    summary = {
        "events": len(events),
        "ips": len(results),
        "blocked": sum(r["verdict"] == "block" for r in results),
        "suspicious": sum(r["verdict"] == "suspicious" for r in results),
        "failed_logins": sum(1 for e in events if e.kind == "failed"),
        "successful_logins": sum(1 for e in events if e.kind == "accepted"),
    }
    return {"summary": summary, "results": results}


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL.spec.get("version"), "storage": type(STORE).__name__}


@app.get("/model")
def model_info():
    return MODEL.spec


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    if len(req.log.encode()) > MAX_LOG_BYTES:
        raise HTTPException(413, "log too large")
    report = analyze_text(req.log, req.year)
    report.update(
        id=uuid.uuid4().hex[:12],
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        host=req.host,
    )
    report["summary"]["host"] = req.host
    if req.save:
        STORE.put(report)
        archive_raw_log(report["id"], req.log)
    return report


@app.get("/reports")
def list_reports(limit: int = 20):
    return STORE.list(min(limit, 100))


@app.get("/reports/{report_id}")
def get_report(report_id: str):
    rep = STORE.get(report_id)
    if not rep:
        raise HTTPException(404, "report not found")
    return rep


@app.get("/blocklist")
def blocklist(report_id: str):
    """Plain-text list of IPs to feed into ufw/iptables/fail2ban."""
    rep = STORE.get(report_id)
    if not rep:
        raise HTTPException(404, "report not found")
    return {"ips": [r["ip"] for r in rep["results"] if r["verdict"] == "block"]}
