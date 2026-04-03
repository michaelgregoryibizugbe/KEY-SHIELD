"""System Information Gatherer v3.0 — robust error handling."""

import platform
import psutil
from datetime import datetime, timezone


def get_system_info() -> dict:
    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Unknown",
        "python_version": platform.python_version(),
        "cpu_count": psutil.cpu_count() or 0,
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "ram_used_percent": psutil.virtual_memory().percent,
    }

    try:
        info["boot_time"] = datetime.fromtimestamp(
            psutil.boot_time(), tz=timezone.utc
        ).isoformat()
    except Exception:
        info["boot_time"] = "Unknown"

    try:
        info["users_logged_in"] = len(psutil.users())
    except Exception:
        info["users_logged_in"] = 0

    try:
        from ..core.config import get_config
        info["profile"] = get_config().profile.name
    except Exception:
        info["profile"] = "standard"

    return info
