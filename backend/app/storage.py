"""Report storage: DynamoDB on AWS, SQLite locally/in Docker. Selected via STORAGE env."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from decimal import Decimal
from typing import List, Optional, Protocol

TTL_DAYS = int(os.getenv("REPORT_TTL_DAYS", "90"))


class Store(Protocol):
    def put(self, report: dict) -> None: ...
    def get(self, report_id: str) -> Optional[dict]: ...
    def list(self, limit: int = 20) -> List[dict]: ...


class SQLiteStore:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, created_at TEXT, body TEXT)"
        )

    def put(self, report: dict) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO reports VALUES (?, ?, ?)",
                (report["id"], report["created_at"], json.dumps(report)),
            )
            self.conn.commit()

    def get(self, report_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT body FROM reports WHERE id = ?", (report_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, limit: int = 20) -> List[dict]:
        rows = self.conn.execute(
            "SELECT body FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_summary(json.loads(r[0])) for r in rows]


class DynamoStore:
    """Single-table design: pk=REPORT, sk=<created_at>#<id>; item 'body' is JSON."""

    def __init__(self, table_name: str):
        import boto3

        self.table = boto3.resource("dynamodb").Table(table_name)

    def put(self, report: dict) -> None:
        self.table.put_item(
            Item={
                "pk": "REPORT",
                "sk": f"{report['created_at']}#{report['id']}",
                "id": report["id"],
                "body": json.dumps(report),
                "expires_at": int(time.time()) + TTL_DAYS * 86400,  # DynamoDB TTL keeps storage tiny
            }
        )

    def get(self, report_id: str) -> Optional[dict]:
        from boto3.dynamodb.conditions import Attr, Key

        resp = self.table.query(
            KeyConditionExpression=Key("pk").eq("REPORT"),
            FilterExpression=Attr("id").eq(report_id),
        )
        items = resp.get("Items", [])
        return json.loads(items[0]["body"]) if items else None

    def list(self, limit: int = 20) -> List[dict]:
        from boto3.dynamodb.conditions import Key

        resp = self.table.query(
            KeyConditionExpression=Key("pk").eq("REPORT"), ScanIndexForward=False, Limit=limit
        )
        return [_summary(json.loads(i["body"])) for i in resp.get("Items", [])]


def _summary(report: dict) -> dict:
    return {k: report[k] for k in ("id", "created_at", "summary")}


def archive_raw_log(report_id: str, text: str) -> None:
    """Keep the raw log in S3 (lifecycle-expired) when ARCHIVE_BUCKET is configured."""
    bucket = os.getenv("ARCHIVE_BUCKET")
    if not bucket:
        return
    import boto3

    boto3.client("s3").put_object(Bucket=bucket, Key=f"raw/{report_id}.log", Body=text.encode())


def make_store() -> Store:
    if os.getenv("STORAGE", "sqlite") == "dynamodb":
        return DynamoStore(os.environ["TABLE_NAME"])
    return SQLiteStore(os.getenv("SQLITE_PATH", ":memory:"))


def to_jsonable(obj):  # pragma: no cover - helper for Decimal from DynamoDB
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError
