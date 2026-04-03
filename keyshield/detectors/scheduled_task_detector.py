"""
Scheduled Task Detector — Windows Task Scheduler + Linux cron analysis.
"""

import os
import platform
import subprocess
from typing import List

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import (
    ThreatLevel, ThreatCategory, SUSPICIOUS_PROCESS_KEYWORDS,
)


class ScheduledTaskDetector(BaseDetector):
    NAME = "ScheduledTaskDetector"

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        system = platform.system()

        if system == "Windows":
            findings.extend(self._scan_windows_tasks())
        elif system == "Linux":
            findings.extend(self._scan_crontabs())
            if not quick:
                findings.extend(self._scan_systemd_timers())

        return findings

    def _scan_windows_tasks(self) -> List[Finding]:
        findings = []
        try:
            result = subprocess.run(
                ["schtasks", "/Query", "/FO", "CSV", "/V"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return findings

            for line in result.stdout.split("\n"):
                line_lower = line.lower()
                matches = [kw for kw in SUSPICIOUS_PROCESS_KEYWORDS if kw in line_lower]
                if matches:
                    # Extract task name (first CSV field)
                    parts = line.split('","')
                    task_name = parts[0].strip('"') if parts else "Unknown"

                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.SCHEDULED_TASK,
                        level=ThreatLevel.HIGH,
                        title=f"Suspicious Scheduled Task: {task_name[:60]}",
                        description=f"Keywords: {', '.join(matches)}",
                        evidence=f"Task: {line[:300]}",
                        recommendation="Review and remove if unauthorized: schtasks /Delete /TN \"<name>\" /F",
                        mitre_id="T1053.005",
                    ))

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return findings

    def _scan_crontabs(self) -> List[Finding]:
        findings = []

        cron_dirs = [
            "/var/spool/cron/",
            "/var/spool/cron/crontabs/",
            "/etc/cron.d/",
        ]
        cron_files = ["/etc/crontab"]

        # Scan cron directories
        for cron_dir in cron_dirs:
            if not os.path.isdir(cron_dir):
                continue
            try:
                for fname in os.listdir(cron_dir):
                    fpath = os.path.join(cron_dir, fname)
                    if os.path.isfile(fpath):
                        findings.extend(self._check_cron_file(fpath))
            except PermissionError:
                continue

        # Scan cron files
        for cron_file in cron_files:
            if os.path.isfile(cron_file):
                findings.extend(self._check_cron_file(cron_file))

        # Current user's crontab
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                for line_num, line in enumerate(result.stdout.split("\n"), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    matches = [kw for kw in SUSPICIOUS_PROCESS_KEYWORDS if kw in line.lower()]
                    if matches:
                        findings.append(Finding(
                            detector=self.NAME,
                            category=ThreatCategory.SCHEDULED_TASK,
                            level=ThreatLevel.HIGH,
                            title=f"Suspicious Crontab Entry (line {line_num})",
                            description=f"Keywords: {', '.join(matches)}",
                            evidence=f"Line: {line[:200]}",
                            recommendation="Review: crontab -e",
                            mitre_id="T1053.003",
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return findings

    def _check_cron_file(self, filepath: str) -> List[Finding]:
        findings = []
        try:
            with open(filepath, "r", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    matches = [kw for kw in SUSPICIOUS_PROCESS_KEYWORDS if kw in line.lower()]
                    if matches:
                        findings.append(Finding(
                            detector=self.NAME,
                            category=ThreatCategory.SCHEDULED_TASK,
                            level=ThreatLevel.HIGH,
                            title=f"Suspicious Cron Entry: {os.path.basename(filepath)}",
                            description=f"Keywords: {', '.join(matches)}",
                            evidence=f"File: {filepath}:{line_num} | {line[:200]}",
                            recommendation="Review and remove if unauthorized.",
                            mitre_id="T1053.003",
                        ))
        except (PermissionError, OSError):
            pass
        return findings

    def _scan_systemd_timers(self) -> List[Finding]:
        findings = []
        try:
            result = subprocess.run(
                ["systemctl", "list-timers", "--all", "--no-pager"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return findings

            for line in result.stdout.split("\n"):
                line_lower = line.lower()
                matches = [kw for kw in SUSPICIOUS_PROCESS_KEYWORDS if kw in line_lower]
                if matches:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.SCHEDULED_TASK,
                        level=ThreatLevel.MEDIUM,
                        title="Suspicious Systemd Timer",
                        description=f"Keywords: {', '.join(matches)}",
                        evidence=f"Timer: {line.strip()[:200]}",
                        mitre_id="T1053.006",
                    ))

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return findings
