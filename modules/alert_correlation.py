from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
import json

# =========================
# Configuration
# =========================
CORRELATION_WINDOW_SECONDS = 600  # 10 minutes
CORRELATION_THRESHOLD = 2
STATE_FILE = Path(".correlation_state.json")


# =========================
# Time Helpers
# =========================
def now_utc():
    return datetime.now(timezone.utc)


# =========================
# Persistent Signal Cache
# =========================
_signal_cache = defaultdict(list)


def load_state():
    if not STATE_FILE.exists():
        return

    try:
        data = json.loads(STATE_FILE.read_text())
    except Exception:
        return

    for ip, signals in data.items():
        for s in signals:
            try:
                ts = datetime.fromisoformat(s["timestamp"])
                _signal_cache[ip].append(
                    (ts, s["severity"], s["reason"])
                )
            except Exception:
                continue


def save_state():
    data = {}

    for ip, signals in _signal_cache.items():
        data[ip] = [
            {
                "timestamp": ts.isoformat(),
                "severity": severity,
                "reason": reason,
            }
            for ts, severity, reason in signals
        ]

    STATE_FILE.write_text(json.dumps(data, indent=2))


# Load state immediately on import
load_state()


# =========================
# Correlation Logic
# =========================
def add_signal(ip: str, severity: str, reason: str) -> bool:
    timestamp = now_utc()
    _signal_cache[ip].append((timestamp, severity, reason))

    # Expire old signals
    cutoff = timestamp.timestamp() - CORRELATION_WINDOW_SECONDS
    _signal_cache[ip] = [
        s for s in _signal_cache[ip]
        if s[0].timestamp() >= cutoff
    ]

    save_state()

    meaningful = [
        s for s in _signal_cache[ip]
        if s[1] in ("MEDIUM", "HIGH")
    ]

    return len(meaningful) >= CORRELATION_THRESHOLD


def clear_signals(ip: str):
    if ip in _signal_cache:
        del _signal_cache[ip]
        save_state()
        
