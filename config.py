import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

INTERFACE = os.getenv("NETSENTINEL_IFACE", "wlan0")
SNORT_ALERT_LOG = Path(os.getenv("NETSENTINEL_SNORT_LOG", "/var/log/snort/alert_json.txt"))
DB_PATH = Path(os.getenv("NETSENTINEL_DB_PATH", str(BASE_DIR / "netsentinel.db")))
POLL_INTERVAL_SEC = float(os.getenv("NETSENTINEL_POLL_INTERVAL", "0.5"))
