"""Persistence Detector v3.0"""
import os, platform
from typing import List
from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import *

class PersistenceDetector(BaseDetector):
    NAME = "PersistenceDetector"
    
    def scan(self, quick=False) -> List[Finding]:
        findings = []
        system = platform.system()
        if system == "Windows":
            findings.extend(self._scan_windows_registry())
            findings.extend(self._scan_windows_startup_folder())
        elif system == "Linux":
            findings.extend(self._scan_linux_persistence())
        elif system == "Darwin":
            findings.extend(self._scan_macos_persistence())
        return findings

    def _scan_windows_registry(self) -> List[Finding]:
        findings = []
        if platform.system() != "Windows":
            return findings
        try:
            import winreg
            for key_path in PERSISTENCE_REGISTRY_KEYS:
                for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        with winreg.OpenKey(hkey, key_path) as key:
                            num_values = winreg.QueryInfoKey(key)[1]
                            for i in range(num_values):
                                name, value, _ = winreg.EnumValue(key, i)
                                value_lower = str(value).lower()
                                matches = [kw for kw in SUSPICIOUS_PROCESS_KEYWORDS if kw in value_lower]
                                if matches:
                                    findings.append(Finding(
                                        detector=self.NAME, category=ThreatCategory.PERSISTENCE,
                                        level=ThreatLevel.HIGH, title=f"Suspicious Registry Run Key: {name}",
                                        description=f"Keywords: {', '.join(matches)}",
                                        evidence=f"Key: {key_path} | Value: {value}",
                                        recommendation="Review this startup entry.", mitre_id="T1547.001"
                                    ))
                    except OSError:
                        continue
        except ImportError:
            pass
        return findings

    def _scan_windows_startup_folder(self) -> List[Finding]:
        findings = []
        if platform.system() != "Windows":
            return findings
        startup_dirs = [
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        ]
        for sdir in startup_dirs:
            if os.path.isdir(sdir):
                try:
                    for fname in os.listdir(sdir):
                        flayer = fname.lower()
                        matches = [kw for kw in SUSPICIOUS_PROCESS_KEYWORDS if kw in flayer]
                        if matches:
                            findings.append(Finding(
                                detector=self.NAME, category=ThreatCategory.PERSISTENCE,
                                level=ThreatLevel.HIGH, title=f"Suspicious Startup File: {fname}",
                                description=f"Keywords: {', '.join(matches)}",
                                evidence=f"Path: {os.path.join(sdir, fname)}",
                                recommendation="Investigate this startup file.", mitre_id="T1547.001"
                            ))
                except OSError:
                    continue
        return findings

    def _scan_linux_persistence(self) -> List[Finding]:
        findings = []
        for path in PERSISTENCE_PATHS_LINUX:
            full_path = os.path.expanduser(path)
            if os.path.exists(full_path):
                if os.path.isdir(full_path):
                    try:
                        for fname in os.listdir(full_path):
                            if self._check_file_for_keywords(os.path.join(full_path, fname)):
                                findings.append(Finding(
                                    detector=self.NAME, category=ThreatCategory.PERSISTENCE,
                                    level=ThreatLevel.HIGH, title=f"Suspicious Persistence: {fname}",
                                    description="Suspicious keywords found in autostart/init file.",
                                    evidence=f"File: {os.path.join(full_path, fname)}",
                                    recommendation="Verify the legitimacy of this persistence mechanism.",
                                    mitre_id="T1547"
                                ))
                    except OSError: continue
                else:
                    if self._check_file_for_keywords(full_path):
                        findings.append(Finding(
                            detector=self.NAME, category=ThreatCategory.PERSISTENCE,
                            level=ThreatLevel.HIGH, title=f"Suspicious Persistence: {os.path.basename(path)}",
                            description="Suspicious keywords found in persistence file.",
                            evidence=f"File: {full_path}", mitre_id="T1547"
                        ))
        return findings

    def _scan_macos_persistence(self) -> List[Finding]:
        findings = []
        for path in PERSISTENCE_PATHS_MACOS:
            full_path = os.path.expanduser(path)
            if os.path.isdir(full_path):
                try:
                    for fname in os.listdir(full_path):
                        if fname.endswith(".plist"):
                            fpath = os.path.join(full_path, fname)
                            if self._check_file_for_keywords(fpath):
                                findings.append(Finding(
                                    detector=self.NAME, category=ThreatCategory.PERSISTENCE,
                                    level=ThreatLevel.HIGH, title=f"Suspicious LaunchAgent/Daemon: {fname}",
                                    description="Keywords matched in plist file.",
                                    evidence=f"File: {fpath}", mitre_id="T1543.001"
                                ))
                except OSError: continue
        return findings

    def _check_file_for_keywords(self, filepath: str) -> bool:
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read().lower()
                return any(kw in content for kw in SUSPICIOUS_PROCESS_KEYWORDS)
        except OSError:
            return False
