"""Memory Scanner v3.0"""
import platform
from typing import List
import psutil
from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import *

class MemoryScanner(BaseDetector):
    NAME = "MemoryScanner"
    
    def scan(self, quick=False) -> List[Finding]:
        findings = []
        findings.extend(self._detect_fileless_indicators())
        if not quick:
            findings.extend(self._detect_memory_anomalies())
        return findings

    def _detect_fileless_indicators(self) -> List[Finding]:
        findings = []
        for proc in self.safe_process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.info["pid"]
                pname = proc.info["name"]
                
                # BUG FIX: Skip kernel threads (PPID 2 on Linux)
                try:
                    if platform.system() == "Linux" and proc.ppid() == 2:
                        continue
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                # BUG FIX: Distinguish between missing file and permission issues
                exe_missing = False
                try:
                    exe = proc.exe()
                    if not exe:
                        exe_missing = True
                except psutil.AccessDenied:
                    # We don't have permission to see the EXE path (common for root/system procs)
                    # This is NOT a threat indicator, just a privilege limitation.
                    continue
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue

                # Process with no executable on disk
                if exe_missing and pid > 4:
                    findings.append(Finding(
                        detector=self.NAME, category=ThreatCategory.MEMORY_THREAT,
                        level=ThreatLevel.HIGH, title=f"Process with no EXE: {pname}",
                        description="Running process has no associated file on disk (possible fileless malware).",
                        evidence=f"PID: {pid}", mitre_id="T1027.002"
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        return findings

    def _detect_memory_anomalies(self) -> List[Finding]:
        findings = []
        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = proc.info["name"]
                
                # Check for large number of threads or high memory usage as weak indicators
                mem = proc.memory_info().rss / (1024 * 1024)
                threads = proc.num_threads()
                
                if mem > 1024 and pname.lower() not in self.config.whitelist:
                    findings.append(Finding(
                        detector=self.NAME, category=ThreatCategory.MEMORY_THREAT,
                        level=ThreatLevel.LOW, title=f"High Memory Usage: {pname}",
                        description=f"Process is using {mem:.1f} MB RAM.",
                        evidence=f"PID: {pid} | Threads: {threads}",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        return findings
