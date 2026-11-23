from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any

from config import INTERFACE, POLL_INTERVAL_SEC, SNORT_ALERT_LOG
from storage import save_alert


def _to_int(val: Any, default: int = 3) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def parse_snort_line(line: str, line_no: int, log_path: Path, iface: str) -> dict[str, Any] | None:
    clean = line.strip()
    if not clean:
        return None

    data = json.loads(clean)
    rule = data.get("rule") if isinstance(data.get("rule"), dict) else {}
    alert_obj = data.get("alert") if isinstance(data.get("alert"), dict) else {}

    signature = str(
        data.get("msg")
        or alert_obj.get("msg")
        or rule.get("msg")
        or data.get("signature")
        or "Snort Alert"
    )

    severity = _to_int(
        data.get("priority")
        or alert_obj.get("priority")
        or rule.get("priority")
        or data.get("severity"),
        default=3,
    )

    return {
        "timestamp": str(data.get("timestamp") or data.get("time") or datetime.now(timezone.utc).isoformat()),
        "iface": iface,
        "src_ip": str(data.get("src_addr") or data.get("src_ip") or "0.0.0.0"),
        "dst_ip": str(data.get("dst_addr") or data.get("dst_ip") or "0.0.0.0"),
        "proto": str(data.get("proto") or data.get("protocol") or "IP").upper(),
        "signature": signature,
        "severity": severity,
        "source": "snort",
        "evidence_ref": f"{log_path}#L{line_no}",
    }


def watch_snort_log(
    log_path: Path = SNORT_ALERT_LOG,
    iface: str = INTERFACE,
    poll_interval: float = POLL_INTERVAL_SEC,
) -> None:
    line_no = 0
    while True:
        if not log_path.exists():
            time.sleep(poll_interval)
            continue

        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            # Переходим в конец текущего файла, чтобы ловить новые алерты
            for _ in f:
                line_no += 1

            while True:
                line = f.readline()
                if not line:
                    try:
                        if f.tell() > log_path.stat().st_size:
                            line_no = 0
                            break
                    except OSError:
                        break
                    time.sleep(poll_interval)
                    continue

                line_no += 1
                try:
                    parsed = parse_snort_line(line, line_no, log_path, iface)
                    if parsed:
                        save_alert(parsed)
                        print(f"[ALERT] {parsed['src_ip']} -> {parsed['dst_ip']} | {parsed['signature']}")
                except json.JSONDecodeError:
                    print(f"[WARN] Битый JSON в строке #{line_no}")