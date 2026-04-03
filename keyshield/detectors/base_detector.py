"""
Base detector with self-exclusion and config access.
All detectors inherit from this to avoid flagging KeyShield itself.
"""

import os
from typing import List

import psutil

from ..core.config import get_config


class BaseDetector:
    """Base class for all detectors — provides self-exclusion and config."""

    NAME = "BaseDetector"

    def __init__(self):
        self.config = get_config()

    def should_skip_process(self, pid: int, pname: str) -> bool:
        """Returns True if the process should NOT be scanned."""
        return self.config.should_skip(pid, pname)

    def safe_process_iter(self, attrs: list):
        """Iterate processes, skipping KeyShield's own and whitelisted processes."""
        for proc in psutil.process_iter(attrs):
            try:
                pid = proc.info.get("pid", 0)
                pname = (proc.info.get("name") or "").lower()

                if self.should_skip_process(pid, pname):
                    continue

                yield proc
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def scan(self, quick: bool = False) -> list:
        raise NotImplementedError
