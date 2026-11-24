import threading
import time
import psutil
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import INTERFACE
from snort_watcher import watch_snort_log
from storage import get_alerts, init_db

app = FastAPI(title="NetSentinel Real-Time API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_last_net = psutil.net_io_counters(pernic=True).get(INTERFACE)
_last_time = time.time()


@app.on_event("startup")
def startup() -> None:
    init_db()
    t = threading.Thread(target=watch_snort_log, daemon=True)
    t.start()


def _map_severity(prio: int) -> str:
    if prio <= 1:
        return "CRITICAL"
    if prio == 2:
        return "WARNING"
    return "INFO"


def _map_score(prio: int) -> float:
    if prio <= 1:
        return 0.92
    if prio == 2:
        return 0.76
    return 0.40


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "interface": INTERFACE}


@app.get("/alerts")
def alerts(limit: int = 50) -> dict:
    raw_alerts = get_alerts(limit=limit)
    formatted = []
    for a in raw_alerts:
        prio = int(a.get("severity", 3))
        formatted.append({
            "id": f"ALRT-{a['id']}",
            "title": a["signature"],
            "severity": _map_severity(prio),
            "description": (
                f"[{a['proto']}] {a['src_ip']} -> {a['dst_ip']} "
                f"on {a['iface']} (ref: {a['evidence_ref']})"
            ),
            "ai_suggestion": "Snort rule triggered. Inspect source IP and packet payload.",
            "anomaly_score": _map_score(prio),
            "timestamp": a["timestamp"],
        })
    return {"interface": INTERFACE, "alerts": formatted}


@app.get("/telemetry")
def telemetry() -> dict:
    global _last_net, _last_time
    now = time.time()
    curr_net = psutil.net_io_counters(pernic=True).get(INTERFACE)

    pps = 0.0
    if curr_net and _last_net and (now - _last_time) > 0:
        dt = now - _last_time
        dpkts = (curr_net.packets_recv + curr_net.packets_sent) - (
            _last_net.packets_recv + _last_net.packets_sent
        )
        pps = round(max(0.0, dpkts / dt), 1)

    _last_net = curr_net
    _last_time = now

    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_freq = psutil.cpu_freq()
    freq_ghz = round((cpu_freq.current / 1000.0), 2) if cpu_freq else 2.4

    recent = get_alerts(limit=1)
    anomaly = 0.15
    if recent:
        anomaly = _map_score(int(recent[0].get("severity", 3)))

    return {
        "interface": INTERFACE,
        "packets_per_sec": pps,
        "anomaly_score": anomaly,
        "cpu_percent": cpu_percent,
        "cpu_freq_ghz": freq_ghz,
        "cpu_status": "HIGH LOAD" if cpu_percent > 80 else "OPTIMAL",
    }
