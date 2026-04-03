"""
Process Detector v3.0
BUG FIX: cpu_percent pre-warm, self-exclusion, refined keywords
"""

import platform
import time
from typing import List, Dict
from collections import defaultdict

import psutil

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import (
    ThreatLevel, ThreatCategory,
    SUSPICIOUS_PROCESS_KEYWORDS,
)


class ProcessDetector(BaseDetector):
    NAME = "ProcessDetector"

    SUSPICIOUS_PARENT_CHILD: Dict[str, List[str]] = {
        "cmd.exe": ["keylog", "hook", "capture", "spy"],
        "powershell.exe": ["keylog", "hook", "capture", "spy"],
        "wscript.exe": ["keylog", "hook"],
        "cscript.exe": ["keylog", "hook"],
        "mshta.exe": ["keylog", "hook"],
        "bash": ["keylog", "hook", "capture", "spy", "pynput"],
        "sh": ["keylog", "hook"],
        "python": ["keylog", "hook", "pynput", "keyboard"],
        "python3": ["keylog", "hook", "pynput", "keyboard"],
    }

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        findings.extend(self._detect_suspicious_parentage())
        findings.extend(self._detect_duplicate_processes())

        if not quick:
            findings.extend(self._detect_recently_spawned())
            if platform.system() == "Linux":
                findings.extend(self._detect_input_device_access())

        return findings

    def _detect_suspicious_parentage(self) -> List[Finding]:
        findings = []

        for proc in self.safe_process_iter(["pid", "name", "ppid", "cmdline"]):
            try:
                pname = (proc.info["name"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()
                ppid = proc.info["ppid"]
                pid = proc.info["pid"]

                if not ppid:
                    continue
                try:
                    parent = psutil.Process(ppid)
                    parent_name = (parent.name() or "").lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                if parent_name not in self.SUSPICIOUS_PARENT_CHILD:
                    continue

                bad_keywords = self.SUSPICIOUS_PARENT_CHILD[parent_name]
                matches = [kw for kw in bad_keywords if kw in pname or kw in cmdline]

                if matches:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.PROCESS_ANOMALY,
                        level=ThreatLevel.HIGH,
                        title=f"Suspicious Child: {proc.info['name']}",
                        description=(
                            f"Spawned by '{parent_name}' with keywords: {', '.join(matches)}"
                        ),
                        evidence=f"PID: {pid} | Parent: {parent_name} (PID: {ppid})",
                        pid=pid, process_name=pname,
                        recommendation="Investigate the parent process chain.",
                        mitre_id="T1059",
                    ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _detect_duplicate_processes(self) -> List[Finding]:
        findings = []
        name_count: Dict[str, List[int]] = defaultdict(list)

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                name_count[pname].append(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        singletons = {"lsass.exe", "wininit.exe", "spoolsv.exe"}
        for pname, pids in name_count.items():
            if pname in singletons and len(pids) > 1:
                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.PROCESS_ANOMALY,
                    level=ThreatLevel.CRITICAL,
                    title=f"Duplicate Critical Process: {pname}",
                    description=f"{len(pids)} instances — may indicate process hollowing.",
                    evidence=f"PIDs: {pids}",
                    recommendation="Verify each instance's binary path.",
                    mitre_id="T1055.012",
                ))

        return findings

    def _detect_recently_spawned(self) -> List[Finding]:
        findings = []
        now = time.time()
        threshold = self.config.profile.recently_spawned_window

        for proc in self.safe_process_iter(["pid", "name", "create_time", "cmdline"]):
            try:
                pname = (proc.info["name"] or "").lower()
                create_time = proc.info.get("create_time", 0)
                cmdline = " ".join(proc.info["cmdline"] or []).lower()
                pid = proc.info["pid"]

                if now - create_time > threshold:
                    continue

                has_keyword = any(kw in pname or kw in cmdline for kw in SUSPICIOUS_PROCESS_KEYWORDS)
                if has_keyword:
                    age = int(now - create_time)
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.PROCESS_ANOMALY,
                        level=ThreatLevel.MEDIUM,
                        title=f"Recently Spawned: {proc.info['name']}",
                        description=f"Suspicious process started {age}s ago.",
                        evidence=f"PID: {pid} | Age: {age}s | CMD: {cmdline[:200]}",
                        pid=pid, process_name=pname,
                        mitre_id="T1204",
                    ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _detect_input_device_access(self) -> List[Finding]:
        findings = []
        legit = {
            "xorg", "x", "wayland", "mutter", "kwin", "gnome-shell",
            "gdm", "sddm", "lightdm", "systemd-logind", "sway", "weston",
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
                    if f.path.startswith(("/dev/input/", "/dev/uinput")):
                        findings.append(Finding(
                            detector=self.NAME,
                            category=ThreatCategory.INPUT_DEVICE_ACCESS,
                            level=ThreatLevel.HIGH,
                            title=f"Input Device Access: {proc.info['name']}",
                            description=f"Open handle: {f.path}",
                            evidence=f"PID: {pid} | Device: {f.path}",
                            pid=pid, process_name=pname,
                            mitre_id="T1056.001",
                        ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings
