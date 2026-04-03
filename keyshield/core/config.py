"""
Configuration system — whitelist, scan profiles, tunable thresholds.
"""

import os
import json
import platform
from dataclasses import dataclass, field
from typing import Set, Dict, Any

from ..utils.helpers import get_data_dir


CONFIG_DIR = get_data_dir()
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


@dataclass
class ScanProfile:
    name: str
    quick: bool = False
    skip_detectors: list = field(default_factory=list)
    clipboard_monitor_time: float = 1.5
    cpu_anomaly_threshold: float = 30.0
    memory_anomaly_threshold: float = 5.0
    connection_count_threshold: int = 50
    recently_spawned_window: int = 300


# Pre-built profiles
PROFILES: Dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick", quick=True,
        skip_detectors=["MemoryScanner", "ScreenCaptureDetector"],
        clipboard_monitor_time=0,
    ),
    "standard": ScanProfile(
        name="standard", quick=False,
        clipboard_monitor_time=1.5,
    ),
    "paranoid": ScanProfile(
        name="paranoid", quick=False,
        cpu_anomaly_threshold=15.0,
        memory_anomaly_threshold=2.0,
        connection_count_threshold=20,
        recently_spawned_window=600,
        clipboard_monitor_time=3.0,
    ),
}


class Config:
    """Manages KeyShield configuration, whitelists, and profiles."""

    # Processes that should NEVER be flagged
    DEFAULT_WHITELIST: Set[str] = {
        # System processes
        "systemd", "init", "launchd", "kernel", "kthreadd",
        "sshd", "cron", "atd", "dbus-daemon", "polkitd",
        # Desktop environments
        "gnome-shell", "plasmashell", "xfce4-panel", "mate-panel",
        "cinnamon", "budgie-panel",
        # Common legitimate tools
        "htop", "top", "btop", "glances", "nmon",
        "code", "vim", "nano", "emacs",
        "firefox", "chrome", "chromium", "brave",
        "thunderbird", "evolution", "geary",
        "nautilus", "dolphin", "thunar", "nemo",
        "terminal", "konsole", "gnome-terminal", "xterm",
        "alacritty", "kitty", "tilix", "tmux", "screen",
        "pulseaudio", "pipewire", "wireplumber",
        "NetworkManager", "wpa_supplicant",
        # Windows legitimate
        "explorer.exe", "taskmgr.exe", "perfmon.exe",
        "mmc.exe", "devenv.exe", "code.exe",
        "msedge.exe", "chrome.exe", "firefox.exe",
        "searchui.exe", "cortana.exe", "sihost.exe",
        "taskhostw.exe", "runtimebroker.exe",
        "applicationframehost.exe", "shellexperiencehost.exe",
        "startmenuexperiencehost.exe", "textinputhost.exe",
    }

    def __init__(self):
        self.whitelist: Set[str] = set(self.DEFAULT_WHITELIST)
        self.profile: ScanProfile = PROFILES["standard"]
        self._own_pids: Set[int] = set()
        self._load_config()
        self._collect_own_pids()

    def _collect_own_pids(self):
        """Collect PIDs belonging to KeyShield itself to avoid self-detection."""
        import psutil
        try:
            current = psutil.Process()
            self._own_pids.add(current.pid)
            # Add parent (the shell that launched us)
            try:
                self._own_pids.add(current.ppid())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            # Add child processes (web server threads, etc.)
            try:
                for child in current.children(recursive=True):
                    self._own_pids.add(child.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        except Exception:
            pass

    def is_own_pid(self, pid: int) -> bool:
        """Check if PID belongs to KeyShield."""
        return pid in self._own_pids

    def is_whitelisted(self, process_name: str) -> bool:
        """Check if process is whitelisted."""
        return process_name.lower().strip() in {w.lower() for w in self.whitelist}

    def should_skip(self, pid: int, process_name: str) -> bool:
        """Check if a process should be skipped entirely."""
        if pid in self._own_pids:
            return True
        if self.is_whitelisted(process_name):
            return True
        # Skip PID 0, 1, 2 (kernel/system)
        if pid < 4:
            return True
        return False

    def set_profile(self, name: str):
        if name in PROFILES:
            self.profile = PROFILES[name]
            self._save_config()

    def add_to_whitelist(self, process_name: str):
        self.whitelist.add(process_name.lower())
        self._save_config()

    def remove_from_whitelist(self, process_name: str):
        self.whitelist.discard(process_name.lower())
        self._save_config()

    def _load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                
                # Load profile
                profile_name = data.get("profile", "standard")
                if profile_name in PROFILES:
                    self.profile = PROFILES[profile_name]
                
                # Load whitelist
                user_whitelist = data.get("whitelist", [])
                self.whitelist.update(w.lower() for w in user_whitelist)
        except Exception:
            pass

    def _save_config(self):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            user_additions = self.whitelist - self.DEFAULT_WHITELIST
            
            config_data = {
                "profile": self.profile.name,
                "whitelist": sorted(user_additions)
            }
            
            with open(CONFIG_FILE, "w") as f:
                json.dump(config_data, f, indent=2)
        except Exception:
            pass

    def to_dict(self) -> dict:
        return {
            "profile": self.profile.name,
            "whitelist_count": len(self.whitelist),
            "own_pids": sorted(self._own_pids),
        }


# Global singleton
_config = None

def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config
