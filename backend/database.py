import sqlite3
import math
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional
from backend.config import settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _db():
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Columns added to the events table after the original schema shipped.
# Each is applied via ALTER TABLE only if missing, so existing populated
# databases migrate in place (old rows get NULLs).
_EVENTS_MIGRATIONS = {
    "scenario_id": "TEXT",     # links a row to a simulation scenario (NULL for live traffic)
    "latency_ms": "REAL",      # detection latency for this request
    "waf_enabled": "INTEGER",  # was the WAF on when this request was processed (1/0)
}


def _migrate(conn: sqlite3.Connection) -> None:
    """Backward-compatible, idempotent schema migration."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
    for column, coltype in _EVENTS_MIGRATIONS.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE events ADD COLUMN {column} {coltype}")

    # WAF runtime state — single-row config plus an append-only audit trail.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS waf_config (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            enabled     INTEGER NOT NULL,
            updated_at  TEXT NOT NULL,
            updated_by  TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS waf_audit (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT NOT NULL,
            actor      TEXT NOT NULL,
            action     TEXT NOT NULL,
            note       TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scenario ON events(scenario_id)")

    # Seed the WAF as enabled the first time only.
    row = conn.execute("SELECT COUNT(*) FROM waf_config").fetchone()
    if row[0] == 0:
        conn.execute(
            "INSERT INTO waf_config (id, enabled, updated_at, updated_by) VALUES (1, 1, ?, 'system')",
            (_now(),),
        )


def init_db() -> None:
    with _db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp         TEXT NOT NULL,
                source_ip         TEXT,
                http_method       TEXT,
                request_uri       TEXT,
                classification    INTEGER NOT NULL,
                confidence_score  REAL NOT NULL,
                attack_type       TEXT,
                action_taken      TEXT NOT NULL,
                payload_fragment  TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_classification ON events(classification)")
        _migrate(conn)
    print("[DB] Initialised — WAL mode enabled, schema migrated")


def log_event(event: dict) -> int:
    sql = """
        INSERT INTO events
            (timestamp, source_ip, http_method, request_uri, classification,
             confidence_score, attack_type, action_taken, payload_fragment,
             scenario_id, latency_ms, waf_enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        event["timestamp"],
        event.get("source_ip"),
        event.get("http_method"),
        event.get("request_uri"),
        event["classification"],
        event["confidence_score"],
        event.get("attack_type"),
        event["action_taken"],
        event.get("payload_fragment"),
        event.get("scenario_id"),
        event.get("latency_ms"),
        event.get("waf_enabled"),
    )
    with _db() as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid


def get_events(
    page: int = 1,
    page_size: int = 20,
    classification: Optional[int] = None,
    attack_type: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> tuple[list[dict], int]:
    conditions = []
    params: list = []

    if classification is not None:
        conditions.append("classification = ?")
        params.append(classification)
    if attack_type is not None:
        conditions.append("attack_type = ?")
        params.append(attack_type)
    if start_time is not None:
        conditions.append("timestamp >= ?")
        params.append(start_time)
    if end_time is not None:
        conditions.append("timestamp <= ?")
        params.append(end_time)
    if source_ip is not None:
        conditions.append("source_ip = ?")
        params.append(source_ip)

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    offset = (page - 1) * page_size

    with _db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [page_size, offset],
        ).fetchall()

    return [dict(r) for r in rows], total


def get_event_by_id(event_id: int) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
    return dict(row) if row else None


def get_summary_stats() -> dict:
    with _db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        # "blocked" = actually blocked by the WAF, not merely malicious. When the
        # WAF is disabled a malicious request is logged (classification=1) but
        # ALLOWED, so counting on action_taken keeps this tile honest.
        blocked = conn.execute(
            "SELECT COUNT(*) FROM events WHERE action_taken LIKE 'BLOCKED%'"
        ).fetchone()[0]
        # Malicious requests that got through — i.e. breaches. High when WAF is off.
        attacks_succeeded = conn.execute(
            "SELECT COUNT(*) FROM events WHERE classification = 1 AND action_taken NOT LIKE 'BLOCKED%'"
        ).fetchone()[0]
        allowed = total - blocked
        detection_rate = round(blocked / total, 6) if total > 0 else 0.0
    return {
        "total_requests": total,
        "blocked": blocked,
        "allowed": allowed,
        "attacks_succeeded": attacks_succeeded,
        "detection_rate": detection_rate,
    }


def get_traffic_series(hours: int = 24) -> list[dict]:
    sql = """
        SELECT
            strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour,
            SUM(CASE WHEN classification = 0 THEN 1 ELSE 0 END) AS legitimate,
            SUM(CASE WHEN classification = 1 THEN 1 ELSE 0 END) AS malicious
        FROM events
        WHERE timestamp >= datetime('now', ?)
        GROUP BY hour
        ORDER BY hour ASC
    """
    with _db() as conn:
        rows = conn.execute(sql, (f"-{hours} hours",)).fetchall()
    return [{"timestamp": r["hour"], "legitimate": r["legitimate"], "malicious": r["malicious"]} for r in rows]


def get_attack_breakdown() -> list[dict]:
    sql = """
        SELECT attack_type, COUNT(*) AS count
        FROM events
        WHERE classification = 1
        GROUP BY attack_type
        ORDER BY count DESC
    """
    with _db() as conn:
        rows = conn.execute(sql).fetchall()
    return [{"attack_type": r["attack_type"] or "Unknown", "count": r["count"]} for r in rows]


# ── WAF runtime state (kill-switch + audit) ────────────────────────────────────

def get_waf_enabled() -> bool:
    with _db() as conn:
        row = conn.execute("SELECT enabled FROM waf_config WHERE id = 1").fetchone()
    # Fail safe: if config somehow missing, treat the WAF as enabled.
    return bool(row["enabled"]) if row else True


def get_waf_status() -> dict:
    with _db() as conn:
        row = conn.execute(
            "SELECT enabled, updated_at, updated_by FROM waf_config WHERE id = 1"
        ).fetchone()
    if not row:
        return {"enabled": True, "updated_at": None, "updated_by": None}
    return {
        "enabled": bool(row["enabled"]),
        "updated_at": row["updated_at"],
        "updated_by": row["updated_by"],
    }


def set_waf_enabled(actor: str, enabled: bool, note: Optional[str] = None) -> dict:
    """Update the kill-switch and append an audit row atomically."""
    now = _now()
    action = "WAF_ENABLED" if enabled else "WAF_DISABLED"
    with _db() as conn:
        conn.execute(
            "UPDATE waf_config SET enabled = ?, updated_at = ?, updated_by = ? WHERE id = 1",
            (1 if enabled else 0, now, actor),
        )
        conn.execute(
            "INSERT INTO waf_audit (timestamp, actor, action, note) VALUES (?, ?, ?, ?)",
            (now, actor, action, note),
        )
    return {"enabled": enabled, "updated_at": now, "updated_by": actor}


def add_waf_audit(actor: str, action: str, note: Optional[str] = None) -> None:
    with _db() as conn:
        conn.execute(
            "INSERT INTO waf_audit (timestamp, actor, action, note) VALUES (?, ?, ?, ?)",
            (_now(), actor, action, note),
        )


def get_waf_audit(limit: int = 50) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, actor, action, note FROM waf_audit ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
