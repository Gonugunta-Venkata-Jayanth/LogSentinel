from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.features import ip_features
from app.main import analyze_text, app
from app.parser import parse_line, parse_log

SAMPLE = (Path(__file__).resolve().parents[2] / "samples" / "auth.log").read_text()

BRUTE = "\n".join(
    f"Oct 30 03:00:{i:02d} web-01 sshd[{900+i}]: Failed password for root from 203.0.113.9 port {40000+i} ssh2"
    for i in range(60)
)
LEGIT = (
    "Oct 30 09:00:00 web-01 sshd[1]: Accepted publickey for jay from 10.0.0.5 port 50000 ssh2\n"
    "Oct 30 13:10:00 web-01 sshd[2]: Accepted publickey for jay from 10.0.0.5 port 50001 ssh2\n"
)


def test_parse_failed_invalid_user():
    ev = parse_line("Oct  5 10:15:01 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2")
    assert ev.kind == "failed" and ev.user == "admin" and ev.ip == "1.2.3.4" and ev.invalid_user
    assert ev.ts.day == 5


def test_parse_iso_and_accepted():
    ev = parse_line("2026-10-30T09:00:00+0530 host sshd[9]: Accepted publickey for jay from 10.0.0.5 port 2 ssh2")
    assert ev.kind == "accepted" and ev.ts.year == 2026


def test_parse_ignores_noise():
    assert parse_line("Oct 30 09:00:00 host CRON[1]: (root) CMD (run-parts)") is None
    assert parse_log("garbage\n\n") == []


def test_features():
    f = ip_features(parse_log(BRUTE))["203.0.113.9"]
    assert f["failed_count"] == 60 and f["root_attempts"] == 60 and f["fail_ratio"] == 1.0
    assert f["attempts_per_min"] == 60


def test_model_separates_obvious_cases():
    rep = analyze_text(BRUTE + "\n" + LEGIT)
    by_ip = {r["ip"]: r for r in rep["results"]}
    assert by_ip["203.0.113.9"]["verdict"] == "block"
    assert by_ip["10.0.0.5"]["verdict"] == "ok"
    assert rep["results"][0]["ip"] == "203.0.113.9"  # sorted by risk


def test_sample_log_finds_attackers():
    rep = analyze_text(SAMPLE)
    assert rep["summary"]["events"] > 100
    assert rep["summary"]["blocked"] + rep["summary"]["suspicious"] >= 6


@pytest.fixture()
def client():
    return TestClient(app)


def test_api_roundtrip(client):
    assert client.get("/health").json()["status"] == "ok"
    r = client.post("/analyze", json={"log": BRUTE, "host": "web-01"})
    assert r.status_code == 200
    rid = r.json()["id"]
    assert any(x["id"] == rid for x in client.get("/reports").json())
    assert client.get(f"/reports/{rid}").json()["summary"]["host"] == "web-01"
    assert client.get("/blocklist", params={"report_id": rid}).json()["ips"] == ["203.0.113.9"]
    assert client.get("/reports/nope").status_code == 404


def test_dynamo_store():
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        ddb = boto3.client("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="t",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        from app.storage import DynamoStore

        store = DynamoStore("t")
        store.put({"id": "a1", "created_at": "2026-10-31T00:00:00", "summary": {"ips": 1}, "results": []})
        store.put({"id": "b2", "created_at": "2026-10-31T01:00:00", "summary": {"ips": 2}, "results": []})
        assert [r["id"] for r in store.list()] == ["b2", "a1"]
        assert store.get("a1")["summary"]["ips"] == 1
        assert store.get("zz") is None
