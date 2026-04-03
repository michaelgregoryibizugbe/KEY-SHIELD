"""
Screen Capture Detector v3.0
BUG FIX: Removed "import" and overly-short "obs" indicators.
"""

import platform
from typing import List

import psutil

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import ThreatLevel, ThreatCategory


class ScreenCaptureDetector(BaseDetector):
    NAME = "ScreenCaptureDetector"

    INDICATORS = [
        "screengrab", "screenshot", "screenspy", "screencap",
        "screenrecord", "desktopdup", "screenpresso", "greenshot",
        "lightshot", "snagit", "gyazo", "printscreen",
        "vnc", "tightvnc", "ultravnc", "teamviewer",
        "anydesk", "rustdesk", "screenshare",
    ]

    LINUX_INDICATORS = [
        "scrot", "maim", "flameshot",
        "recordmydesktop", "simplescreenrecorder",
        "kazam", "peek", "obs-studio", "obs64",
        "x11vnc", "vino", "krfb",
        # "import" REMOVED — too generic (matches Python import statements)
        # "obs" REMOVED — too short (matches "jobserver", etc.)
    ]

    LEGITIMATE: set = {
        "snippingtool.exe", "snipandsketch.exe", "screensketch.exe",
        "gnome-screenshot", "spectacle", "flameshot",
    }

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        findings.extend(self._detect_capture_processes())

        if not quick:
            if platform.system() == "Windows":
                findings.extend(self._detect_gdi_capture())
            elif platform.system() == "Linux":
                findings.extend(self._detect_framebuffer_access())

        return findings

    def _detect_capture_processes(self) -> List[Finding]:
        findings = []
        indicators = list(self.INDICATORS)
        if platform.system() == "Linux":
            indicators.extend(self.LINUX_INDICATORS)

        for proc in self.safe_process_iter(["pid", "name", "cmdline"]):
            try:
                pname = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()
                searchable = f"{pname} {cmdline}"

                if pname in self.LEGITIMATE:
                    continue

                matches = [i for i in indicators if i in searchable]
                if not matches:
                    continue

                remote_tools = ["vnc", "teamviewer", "anydesk", "rustdesk", "x11vnc"]
                is_remote = any(r in searchable for r in remote_tools)
                level = ThreatLevel.HIGH if is_remote else ThreatLevel.MEDIUM

                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.SCREEN_CAPTURE,
                    level=level,
                    title=f"Screen Capture: {proc.info['name']}",
                    description=f"Indicators: {', '.join(matches)}",
                    evidence=f"PID: {proc.info['pid']}",
                    pid=proc.info["pid"], process_name=pname,
                    recommendation="Verify this tool is authorized.",
                    mitre_id="T1113",
                ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _detect_framebuffer_access(self) -> List[Finding]:
        findings = []
        legit_fb = {"xorg", "x", "wayland", "gnome-shell", "mutter", "kwin", "sway", "weston"}

        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = (proc.info["name"] or "").lower()
                if pname in legit_fb:
                    continue

                try:
                    fds = psutil.Process(pid).open_files()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                for fd in fds:
                    if fd.path.startswith(("/dev/fb", "/dev/dri/")):
                        findings.append(Finding(
                            detector=self.NAME,
                            category=ThreatCategory.SCREEN_CAPTURE,
                            level=ThreatLevel.HIGH,
                            title=f"Framebuffer Access: {proc.info['name']}",
                            description=f"Reading: {fd.path}",
                            evidence=f"PID: {pid}",
                            pid=pid, process_name=pname,
                            mitre_id="T1113",
                        ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _detect_gdi_capture(self) -> List[Finding]:
        findings = []
        skip = {"dwm.exe", "csrss.exe", "explorer.exe", "svchost.exe", "system"}

        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = (proc.info["name"] or "").lower()
                if pname in skip or pid < 10:
                    continue

                try:
                    dlls = [m.path.lower() for m in psutil.Process(pid).memory_maps() if m.path]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                has_gdi = any("gdi32" in d or "d3d11" in d for d in dlls)
                has_name = any(k in pname for k in ["capture", "record", "screen", "grab"])

                if has_gdi and has_name:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.SCREEN_CAPTURE,
                        level=ThreatLevel.MEDIUM,
                        title=f"GDI Capture: {proc.info['name']}",
                        description="Loads GDI32 with screen-related name.",
                        evidence=f"PID: {pid}",
                        pid=pid, process_name=pname,
                        mitre_id="T1113",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings
