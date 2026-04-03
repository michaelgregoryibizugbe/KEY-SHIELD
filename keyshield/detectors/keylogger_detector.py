"""
Keylogger Detector v3.0
- Self-exclusion via BaseDetector
- Refined keyword matching
- Platform-aware signature filtering
"""

import os
import platform
from typing import List

import psutil

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import (
    KNOWN_KEYLOGGER_PROCESSES,
    SUSPICIOUS_PROCESS_KEYWORDS,
    WEAK_SUSPICIOUS_KEYWORDS,
    KEYLOG_OUTPUT_PATTERNS,
    ThreatLevel,
    ThreatCategory,
)


class KeyloggerDetector(BaseDetector):
    NAME = "KeyloggerDetector"

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        current_platform = platform.system().lower()

        findings.extend(self._scan_known_signatures(current_platform))
        findings.extend(self._scan_keyword_heuristics())

        if not quick:
            findings.extend(self._scan_suspicious_files())

        return findings

    def _scan_known_signatures(self, current_platform: str) -> List[Finding]:
        findings = []
        already_found_pids = set()

        for proc in self.safe_process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                pname = (proc.info["name"] or "").lower()
                pexe = (proc.info["exe"] or "").lower()
                cmdline = " ".join(proc.info["cmdline"] or []).lower()
                pid = proc.info["pid"]
                searchable = f"{pname} {pexe} {cmdline}"

                for key, sig in KNOWN_KEYLOGGER_PROCESSES.items():
                    # Skip signatures not for this platform
                    if current_platform not in sig.platforms:
                        continue

                    for indicator in sig.indicators:
                        if indicator in searchable:
                            already_found_pids.add(pid)
                            kill_cmd = (
                                f"taskkill /PID {pid} /F"
                                if platform.system() == "Windows"
                                else f"kill -9 {pid}"
                            )
                            findings.append(Finding(
                                detector=self.NAME,
                                category=sig.category,
                                level=sig.level,
                                title=f"Known Keylogger: {sig.name}",
                                description=sig.description,
                                evidence=(
                                    f"PID: {pid} | Process: {pname} | "
                                    f"Match: '{indicator}'"
                                ),
                                pid=pid,
                                process_name=pname,
                                recommendation=f"Terminate immediately: {kill_cmd}",
                                mitre_id=sig.mitre_id,
                            ))
                            break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _scan_keyword_heuristics(self) -> List[Finding]:
        findings = []

        for proc in self.safe_process_iter(["pid", "name", "cmdline"]):
            try:
                pname = (proc.info["name"] or "").lower()
                pid = proc.info["pid"]
                cmdline = " ".join(proc.info["cmdline"] or []).lower()
                searchable = f"{pname} {cmdline}"

                # Strong keywords: 1 match = flag
                strong_matches = [
                    kw for kw in SUSPICIOUS_PROCESS_KEYWORDS
                    if kw in searchable
                ]

                # Weak keywords: need 2+ matches
                weak_matches = [
                    kw for kw in WEAK_SUSPICIOUS_KEYWORDS
                    if kw in searchable
                ]

                if strong_matches:
                    level = (
                        ThreatLevel.HIGH if len(strong_matches) >= 2
                        else ThreatLevel.MEDIUM
                    )
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.KEYLOGGER,
                        level=level,
                        title=f"Suspicious Process: {proc.info['name']}",
                        description=(
                            f"Matches {len(strong_matches)} suspicious keyword(s): "
                            f"{', '.join(strong_matches)}"
                        ),
                        evidence=f"PID: {pid} | Name: {pname} | CMD: {cmdline[:200]}",
                        pid=pid,
                        process_name=pname,
                        recommendation="Investigate this process origin and behavior.",
                        mitre_id="T1056.001",
                    ))
                elif len(weak_matches) >= 2:
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.KEYLOGGER,
                        level=ThreatLevel.LOW,
                        title=f"Mildly Suspicious Process: {proc.info['name']}",
                        description=(
                            f"Matches {len(weak_matches)} weak indicators: "
                            f"{', '.join(weak_matches)}"
                        ),
                        evidence=f"PID: {pid} | Name: {pname}",
                        pid=pid,
                        process_name=pname,
                        recommendation="Review if this process is expected.",
                        mitre_id="T1056.001",
                    ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _scan_suspicious_files(self) -> List[Finding]:
        findings = []
        temp_dirs = self._get_temp_dirs()

        for temp_dir in temp_dirs:
            if not os.path.isdir(temp_dir):
                continue
            try:
                for root, _, files in os.walk(temp_dir):
                    depth = root.replace(temp_dir, "").count(os.sep)
                    if depth > 2:
                        dirs_to_skip = True
                        break

                    for fname in files:
                        fname_lower = fname.lower()
                        for pattern in KEYLOG_OUTPUT_PATTERNS:
                            if pattern in fname_lower:
                                fpath = os.path.join(root, fname)
                                try:
                                    fsize = os.path.getsize(fpath)
                                except OSError:
                                    fsize = 0

                                findings.append(Finding(
                                    detector=self.NAME,
                                    category=ThreatCategory.KEYLOGGER,
                                    level=ThreatLevel.HIGH,
                                    title=f"Keylogger Output File: {fname}",
                                    description=f"Matches pattern '{pattern}' in temp dir.",
                                    evidence=f"File: {fpath} | Size: {fsize} bytes",
                                    recommendation="Quarantine and examine this file.",
                                    mitre_id="T1074",
                                ))
                                break
            except (PermissionError, OSError):
                continue

        return findings

    @staticmethod
    def _get_temp_dirs() -> List[str]:
        dirs = []
        if platform.system() == "Windows":
            for var in ("TEMP", "TMP"):
                val = os.environ.get(var, "")
                if val:
                    dirs.append(val)
            localappdata = os.environ.get("LOCALAPPDATA", "")
            if localappdata:
                dirs.append(os.path.join(localappdata, "Temp"))
        else:
            dirs.extend(["/tmp", "/var/tmp", os.path.expanduser("~/.cache")])
        return [d for d in dirs if d and os.path.isdir(d)]
