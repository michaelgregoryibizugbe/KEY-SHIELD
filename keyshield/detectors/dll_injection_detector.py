"""DLL/SO Injection Detector v3.0 — inherits BaseDetector for self-exclusion."""

import os
import platform
from typing import List

import psutil

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import (
    ThreatLevel, ThreatCategory,
    KNOWN_MALICIOUS_DLLS, KNOWN_MALICIOUS_SOS, SYSTEM_SO_WHITELIST,
)


class DLLInjectionDetector(BaseDetector):
    NAME = "DLLInjectionDetector"

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        system = platform.system()

        if system == "Windows":
            findings.extend(self._detect_malicious_dlls())
            if not quick:
                findings.extend(self._detect_unusual_dll_paths())
        elif system == "Linux":
            findings.extend(self._detect_malicious_so())
            if not quick:
                findings.extend(self._detect_unusual_so_maps())

        return findings

    def _detect_malicious_dlls(self) -> List[Finding]:
        findings = []
        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = (proc.info["name"] or "").lower()
                try:
                    modules = [m.path for m in psutil.Process(pid).memory_maps() if m.path]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                for mp in modules:
                    mn = os.path.basename(mp).lower()
                    if any(d in mn for d in KNOWN_MALICIOUS_DLLS):
                        findings.append(Finding(
                            detector=self.NAME, category=ThreatCategory.DLL_INJECTION,
                            level=ThreatLevel.CRITICAL,
                            title=f"Malicious DLL: {mn}",
                            description=f"Known hooking DLL in '{pname}'.",
                            evidence=f"PID: {pid} | DLL: {mp}",
                            pid=pid, process_name=pname,
                            recommendation="Remove immediately.",
                            mitre_id="T1055.001",
                        ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return findings

    def _detect_unusual_dll_paths(self) -> List[Finding]:
        findings = []
        system_dirs = [
            "c:\\windows\\system32", "c:\\windows\\syswow64",
            "c:\\windows\\winsxs", "c:\\program files", "c:\\program files (x86)",
        ]
        critical = {"lsass.exe", "svchost.exe", "csrss.exe", "winlogon.exe", "services.exe"}

        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname not in critical:
                    continue
                pid = proc.info["pid"]
                try:
                    modules = [m.path for m in psutil.Process(pid).memory_maps() if m.path]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                for mp in modules:
                    pl = mp.lower()
                    if not any(pl.startswith(sd) for sd in system_dirs):
                        mn = os.path.basename(mp).lower()
                        if mn.endswith(".dll"):
                            findings.append(Finding(
                                detector=self.NAME, category=ThreatCategory.DLL_INJECTION,
                                level=ThreatLevel.HIGH,
                                title=f"Non-System DLL in {pname}: {mn}",
                                description="DLL from non-standard path in critical process.",
                                evidence=f"PID: {pid} | DLL: {mp}",
                                pid=pid, process_name=pname,
                                mitre_id="T1055.001",
                            ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return findings

    def _detect_malicious_so(self) -> List[Finding]:
        findings = []
        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = (proc.info["name"] or "").lower()
                maps_file = f"/proc/{pid}/maps"
                try:
                    with open(maps_file, "r") as f:
                        data = f.read(100000)
                except (PermissionError, OSError, FileNotFoundError):
                    continue

                for mal_so in KNOWN_MALICIOUS_SOS:
                    if mal_so in data.lower():
                        findings.append(Finding(
                            detector=self.NAME, category=ThreatCategory.SO_INJECTION,
                            level=ThreatLevel.CRITICAL,
                            title=f"Malicious SO: {mal_so}",
                            description=f"Loaded in '{pname}'.",
                            evidence=f"PID: {pid} | SO: {mal_so}",
                            pid=pid, process_name=pname,
                            mitre_id="T1055.009",
                        ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return findings

    def _detect_unusual_so_maps(self) -> List[Finding]:
        findings = []
        standard = {"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/snap/", "/opt/"}
        sensitive = {"sshd", "login", "sudo", "su", "passwd"}

        for proc in self.safe_process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = (proc.info["name"] or "").lower()
                if pname not in sensitive:
                    continue

                try:
                    with open(f"/proc/{pid}/maps", "r") as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) < 6:
                                continue
                            path = parts[5]
                            if (".so" in path) and path.startswith("/"):
                                if not any(path.startswith(sd) for sd in standard):
                                    so_name = os.path.basename(path)
                                    if not any(wl in so_name for wl in SYSTEM_SO_WHITELIST):
                                        findings.append(Finding(
                                            detector=self.NAME, category=ThreatCategory.SO_INJECTION,
                                            level=ThreatLevel.HIGH,
                                            title=f"Non-Standard SO in {pname}: {so_name}",
                                            description="Unusual library in sensitive process.",
                                            evidence=f"PID: {pid} | SO: {path}",
                                            pid=pid, process_name=pname,
                                            mitre_id="T1055.009",
                                        ))
                except (PermissionError, OSError, FileNotFoundError):
                    continue
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return findings
