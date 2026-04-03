"""
Clipboard Monitor v3.0
BUG FIX: Windows CF_UNICODETEXT, reduced blocking time.
"""

import platform
import time
import hashlib
from typing import List, Optional

import psutil

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import ThreatLevel, ThreatCategory


class ClipboardMonitor(BaseDetector):
    NAME = "ClipboardMonitor"

    CLIPBOARD_INDICATORS = [
        "clipgrab", "clipspy", "clipmon", "pastejack",
        "clipbanker", "clip_hijack", "clipstealer",
    ]

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        findings.extend(self._detect_clipboard_processes())

        if not quick and self.config.profile.clipboard_monitor_time > 0:
            findings.extend(self._detect_clipboard_rapid_change())

        return findings

    def _detect_clipboard_processes(self) -> List[Finding]:
        findings = []

        for proc in self.safe_process_iter(["pid", "name", "cmdline"]):
            try:
                pname = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()
                searchable = f"{pname} {cmdline}"

                matches = [ind for ind in self.CLIPBOARD_INDICATORS if ind in searchable]
                if matches:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.CLIPBOARD_HIJACK,
                        level=ThreatLevel.HIGH,
                        title=f"Clipboard Hijacker: {proc.info['name']}",
                        description=f"Indicators: {', '.join(matches)}",
                        evidence=f"PID: {proc.info['pid']} | CMD: {cmdline[:200]}",
                        pid=proc.info["pid"], process_name=pname,
                        recommendation="Clipboard hijackers swap crypto addresses. Terminate immediately.",
                        mitre_id="T1115",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _detect_clipboard_rapid_change(self) -> List[Finding]:
        findings = []
        monitor_time = self.config.profile.clipboard_monitor_time

        try:
            content = self._get_clipboard_content()
            if content is None:
                return findings

            initial_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
            changes = 0
            checks = int(monitor_time / 0.5)

            for _ in range(max(checks, 1)):
                time.sleep(0.5)
                current = self._get_clipboard_content()
                if current is None:
                    continue
                h = hashlib.sha256(current.encode("utf-8", errors="ignore")).hexdigest()
                if h != initial_hash:
                    changes += 1
                    initial_hash = h

            if changes >= 3:
                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.CLIPBOARD_HIJACK,
                    level=ThreatLevel.HIGH,
                    title="Rapid Clipboard Modification",
                    description=f"Changed {changes} times in {monitor_time}s.",
                    evidence=f"Changes: {changes}",
                    recommendation="Check for crypto-address swapping malware.",
                    mitre_id="T1115",
                ))
        except Exception:
            pass

        return findings

    @staticmethod
    def _get_clipboard_content() -> Optional[str]:
        system = platform.system()
        try:
            if system == "Windows":
                import ctypes
                CF_UNICODETEXT = 13  # BUG FIX: was CF_TEXT=1 (ASCII only)
                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32

                if not user32.OpenClipboard(0):
                    return None
                try:
                    handle = user32.GetClipboardData(CF_UNICODETEXT)
                    if handle:
                        kernel32.GlobalLock.restype = ctypes.c_wchar_p
                        data = kernel32.GlobalLock(handle)
                        if data:
                            text = str(data)
                            kernel32.GlobalUnlock(handle)
                            return text
                finally:
                    user32.CloseClipboard()

            elif system == "Linux":
                import subprocess
                # Try xclip, fall back to xsel
                for cmd in [
                    ["xclip", "-selection", "clipboard", "-o"],
                    ["xsel", "--clipboard", "--output"],
                ]:
                    try:
                        result = subprocess.run(
                            cmd, capture_output=True, text=True, timeout=2
                        )
                        if result.returncode == 0:
                            return result.stdout
                    except FileNotFoundError:
                        continue
                return None

            elif system == "Darwin":
                import subprocess
                result = subprocess.run(
                    ["pbpaste"], capture_output=True, text=True, timeout=2
                )
                return result.stdout if result.returncode == 0 else None

        except Exception:
            return None
        return None
