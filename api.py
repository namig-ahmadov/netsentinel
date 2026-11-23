import threading
from fastapi import FastAPI

from config import INTERFACE
from snort_watcher import watch_snort_log
from storage import get_alerts, init_db

app = FastAPI(title="NetSentinel Basic Snort API")


@app.on_event("startup")
def startup() -> None:
    init_db()
    t = threading.Thread(target=watch_snort_log, daemon=True)
    t.start()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "interface": INTERFACE}


@app.get("/alerts")
def alerts(limit: int = 50) -> dict:
    return {"interface": INTERFACE, "alerts": get_alerts(limit=limit)}