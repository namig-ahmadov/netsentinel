import sqlite3
from pathlib import Path
from typing import Any

from config import DB_PATH


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        iface TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        proto TEXT NOT NULL,
        signature TEXT NOT NULL,
        severity INTEGER NOT NULL,
        source TEXT NOT NULL,
        evidence_ref TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()


def save_alert(alert: dict[str, Any], db_path: Path = DB_PATH) -> int:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO alerts (
            timestamp, iface, src_ip, dst_ip, proto,
            signature, severity, source, evidence_ref
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert["timestamp"],
            alert["iface"],
            alert["src_ip"],
            alert["dst_ip"],
            alert["proto"],
            alert["signature"],
            alert["severity"],
            alert["source"],
            alert["evidence_ref"],
        ),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return int(row_id)


def get_alerts(limit: int = 50, db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]