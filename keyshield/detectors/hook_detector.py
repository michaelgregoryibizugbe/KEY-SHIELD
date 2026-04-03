"""
Hook Detector v3.0 — Cross-platform.
BUG FIXES: removed unused imports, refined xinput matching.
"""

import os
import platform
from typing import List

import psutil

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import ThreatLevel, ThreatCategory


class HookDetector(BaseDetector):
    NAME = "HookDetector"

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        system = platform.system()

        if system == "Windows":
            findings.extend(self._detect_windows_hooks())
            if not quick:
                findings.extend(self._scan_windows_api_imports())
        elif system == "Linux":
            findings.extend(self._detect_ld_preload())
            findings.extend(self._detect_ptrace_scope())
            findings.extend(self._detect_xinput_hooks())
            findings.extend(self._detect_dev_input_access())
            if not quick:
                findings.extend(self._detect_xrecord_usage())

        return findings

    # ── Linux ────────────────────────────────────────────

    def _detect_ld_preload(self) -> List[Finding]:
        findings = []

        preload_file = "/etc/ld.so.preload"
        if os.path.exists(preload_file):
            try:
                with open(preload_file, "r") as f:
                    content = f.read().strip()
                if content:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.LD_PRELOAD,
                        level=ThreatLevel.CRITICAL,
                        title="System-Wide LD_PRELOAD Injection",
                        description="Libraries in /etc/ld.so.preload inject into ALL processes.",
                        evidence=f"Content: {content[:300]}",
                        recommendation="sudo truncate -s 0 /etc/ld.so.preload",
                        mitre_id="T1574.006",
                    ))
            except PermissionError:
                pass

        safe_preloads = {
            "libgtk3-nocsd", "libnss", "libfakeroot", "libjemalloc", 
            "libeatmydata", "libmozsandbox.so"
        }

        for proc in self.safe_process_iter(["pid", "name", "environ"]):
            try:
                env = proc.info.get("environ")
                if not isinstance(env, dict):
                    continue
                ld_val = env.get("LD_PRELOAD", "")
                if not ld_val:
                    continue

                if any(s in ld_val for s in safe_preloads):
                    continue

                pname = proc.info["name"] or ""
                pid = proc.info["pid"]
                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.LD_PRELOAD,
                    level=ThreatLevel.HIGH,
                    title=f"LD_PRELOAD on: {pname}",
                    description="Process has LD_PRELOAD injecting libraries.",
                    evidence=f"PID: {pid} | LD_PRELOAD={ld_val[:200]}",
                    pid=pid, process_name=pname,
                    recommendation="Verify this LD_PRELOAD is authorized.",
                    mitre_id="T1574.006",
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _detect_ptrace_scope(self) -> List[Finding]:
        findings = []
        ptrace_file = "/proc/sys/kernel/yama/ptrace_scope"
        if os.path.exists(ptrace_file):
            try:
                with open(ptrace_file) as f:
                    scope = f.read().strip()
                if scope == "0":
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.PTRACE_INJECTION,
                        level=ThreatLevel.MEDIUM,
                        title="Ptrace Scope Permissive (0)",
                        description="Any process can ptrace any same-user process.",
                        evidence=f"ptrace_scope = {scope}",
                        recommendation="echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope",
                        mitre_id="T1055.008",
                    ))
            except (PermissionError, OSError):
                pass
        return findings

    def _detect_xinput_hooks(self) -> List[Finding]:
        findings = []

        # Specific malicious indicators (not the xinput utility itself)
        malicious_indicators = ["xspy", "xkeylog", "xgrabkeyboard"]

        for proc in self.safe_process_iter(["pid", "name", "cmdline"]):
            try:
                pname = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()
                searchable = f"{pname} {cmdline}"

                matches = [i for i in malicious_indicators if i in searchable]
                if matches:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.INPUT_HOOK,
                        level=ThreatLevel.HIGH,
                        title=f"X11 Input Hook: {proc.info['name']}",
                        description=f"Indicators: {', '.join(matches)}",
                        evidence=f"PID: {proc.info['pid']} | CMD: {cmdline[:200]}",
                        pid=proc.info["pid"], process_name=pname,
                        recommendation="Verify this X11 input capture is authorized.",
                        mitre_id="T1056.001",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _detect_dev_input_access(self) -> List[Finding]:
        findings = []
        legit = {
            "xorg", "x", "wayland", "mutter", "kwin", "gnome-shell",
            "gdm", "sddm", "lightdm", "systemd-logind", "weston", "sway",
            "libinput", "inputattach",
        }

        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = (proc.info["name"] or "").lower()
                if pname in legit:
                    continue

                try:
                    open_files = psutil.Process(pid).open_files()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                for f in open_files:
                    if f.path.startswith(("/dev/input/", "/dev/uinput", "/dev/hidraw")):
                        findings.append(Finding(
                            detector=self.NAME,
                            category=ThreatCategory.INPUT_DEVICE_ACCESS,
                            level=ThreatLevel.HIGH,
                            title=f"Input Device Access: {proc.info['name']}",
                            description=f"Reading: {f.path}",
                            evidence=f"PID: {pid} | Device: {f.path}",
                            pid=pid, process_name=pname,
                            mitre_id="T1056.001",
                        ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _detect_xrecord_usage(self) -> List[Finding]:
        findings = []
        legit = {"xdotool", "xorg", "xvfb", "barrier", "synergy", "at-spi2-registryd"}

        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = (proc.info["name"] or "").lower()
                if pid < 100 or pname in legit:
                    continue

                maps_file = f"/proc/{pid}/maps"
                try:
                    with open(maps_file, "r") as f:
                        content = f.read(50000)  # Cap read size
                except (PermissionError, OSError, FileNotFoundError):
                    continue

                if "libXtst" in content or "libxtst" in content:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.INPUT_HOOK,
                        level=ThreatLevel.MEDIUM,
                        title=f"XRecord Library: {proc.info['name']}",
                        description="libXtst loaded — can record keyboard/mouse.",
                        evidence=f"PID: {pid} | Library: libXtst",
                        pid=pid, process_name=pname,
                        mitre_id="T1056.001",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    # ── Windows ──────────────────────────────────────────

    def _detect_windows_hooks(self) -> List[Finding]:
        findings = []
        hook_dlls = ["easyhook", "mhook", "detours", "minhook", "hookshark", "apihook", "madcodehook"]

        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = (proc.info["name"] or "").lower()

                try:
                    dlls = [m.path.lower() for m in psutil.Process(pid).memory_maps() if m.path]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                found = [d for d in dlls if any(h in d for h in hook_dlls)]
                if found:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.INPUT_HOOK,
                        level=ThreatLevel.HIGH,
                        title=f"Hook Library: {proc.info['name']}",
                        description="Known hooking DLLs loaded.",
                        evidence=f"PID: {pid} | DLLs: {', '.join(found[:3])}",
                        pid=pid, process_name=pname,
                        mitre_id="T1056.001",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _scan_windows_api_imports(self) -> List[Finding]:
        findings = []
        system_procs = {
            "system", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "dwm.exe", "winlogon.exe", "taskhostw.exe",
        }

        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname in system_procs:
                    continue
                pid = proc.info["pid"]

                try:
                    dlls = [m.path.lower() for m in psutil.Process(pid).memory_maps() if m.path]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                count = sum(1 for d in dlls if any(k in d for k in ["hook", "inject", "intercept"]))
                if count >= 2:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.INPUT_HOOK,
                        level=ThreatLevel.MEDIUM,
                        title=f"Suspicious Modules: {proc.info['name']}",
                        description=f"{count} hook/inject modules loaded.",
                        evidence=f"PID: {pid}",
                        pid=pid, process_name=pname,
                        mitre_id="T1056.001",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings
