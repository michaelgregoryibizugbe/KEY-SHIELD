"""
Network Exfiltration Detector v3.0
BUG FIX: Separated hard suspicious ports from contextual ones, dedup.
"""

import platform
from typing import List, Dict, Set
from collections import defaultdict

import psutil

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import (
    ThreatLevel, ThreatCategory,
    SUSPICIOUS_PORTS, SUSPICIOUS_PORTS_CONTEXTUAL,
    SUSPICIOUS_PROCESS_KEYWORDS,
)


class NetworkExfilDetector(BaseDetector):
    NAME = "NetworkExfilDetector"

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        findings.extend(self._detect_suspicious_connections())

        if not quick:
            findings.extend(self._detect_connection_anomalies())
            findings.extend(self._detect_dns_exfiltration())

        return findings

    def _detect_suspicious_connections(self) -> List[Finding]:
        findings = []
        flagged_pids: Set[int] = set()

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return findings

        for conn in connections:
            if conn.status not in ("ESTABLISHED", "SYN_SENT"):
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid

            if not pid or pid in flagged_pids:
                continue
            if remote_ip.startswith("127.") or remote_ip == "::1":
                continue
            if self.config.is_own_pid(pid):
                continue

            pname = self._get_process_name(pid)

            # Hard suspicious ports — always flag
            if remote_port in SUSPICIOUS_PORTS:
                flagged_pids.add(pid)
                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.NETWORK_EXFILTRATION,
                    level=ThreatLevel.HIGH,
                    title=f"Suspicious Port: {remote_port}",
                    description=f"'{pname}' connected to {remote_ip}:{remote_port}.",
                    evidence=f"PID: {pid} | Remote: {remote_ip}:{remote_port}",
                    pid=pid, process_name=pname,
                    recommendation=f"Investigate connection to {remote_ip}:{remote_port}.",
                    mitre_id="T1041",
                ))

            # Contextual ports — only if process name is suspicious
            elif remote_port in SUSPICIOUS_PORTS_CONTEXTUAL:
                if pname and any(kw in pname.lower() for kw in SUSPICIOUS_PROCESS_KEYWORDS):
                    flagged_pids.add(pid)
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.NETWORK_EXFILTRATION,
                        level=ThreatLevel.MEDIUM,
                        title=f"Suspicious Process on Port {remote_port}",
                        description=f"Suspicious process '{pname}' using common service port.",
                        evidence=f"PID: {pid} | Remote: {remote_ip}:{remote_port}",
                        pid=pid, process_name=pname,
                        mitre_id="T1041",
                    ))

            # Any suspicious-named process with outbound connections
            elif pname and any(kw in pname.lower() for kw in SUSPICIOUS_PROCESS_KEYWORDS[:10]):
                if pid not in flagged_pids:
                    flagged_pids.add(pid)
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.NETWORK_EXFILTRATION,
                        level=ThreatLevel.CRITICAL,
                        title=f"Suspicious Process Phoning Home: {pname}",
                        description=f"Outbound connection from suspicious process.",
                        evidence=f"PID: {pid} | Remote: {remote_ip}:{remote_port}",
                        pid=pid, process_name=pname,
                        recommendation="Investigate immediately.",
                        mitre_id="T1041",
                    ))

        return findings

    def _detect_connection_anomalies(self) -> List[Finding]:
        findings = []
        threshold = self.config.profile.connection_count_threshold

        try:
            proc_connections: Dict[int, int] = defaultdict(int)
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid and not self.config.is_own_pid(conn.pid):
                    proc_connections[conn.pid] += 1

            legit = {"chrome", "firefox", "edge", "brave", "svchost", "system", "httpd", "nginx"}

            for pid, count in proc_connections.items():
                if count <= threshold:
                    continue
                pname = self._get_process_name(pid)
                if any(l in pname.lower() for l in legit):
                    continue

                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.NETWORK_EXFILTRATION,
                    level=ThreatLevel.MEDIUM,
                    title=f"High Connections: {pname} ({count})",
                    description=f"Process has {count} active connections.",
                    evidence=f"PID: {pid} | Connections: {count}",
                    pid=pid, process_name=pname or "",
                    mitre_id="T1071",
                ))
        except (psutil.AccessDenied, PermissionError):
            pass

        return findings

    def _detect_dns_exfiltration(self) -> List[Finding]:
        findings = []
        try:
            dns_counts: Dict[int, int] = defaultdict(int)
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.raddr.port == 53 and conn.pid:
                    if not self.config.is_own_pid(conn.pid):
                        dns_counts[conn.pid] += 1

            dns_services = {"systemd-resolve", "dnsmasq", "unbound", "svchost"}
            for pid, count in dns_counts.items():
                if count <= 10:
                    continue
                pname = self._get_process_name(pid)
                if any(d in pname.lower() for d in dns_services):
                    continue

                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.NETWORK_EXFILTRATION,
                    level=ThreatLevel.MEDIUM,
                    title=f"DNS Tunneling Suspect: {pname}",
                    description=f"{count} DNS connections — possible exfiltration.",
                    evidence=f"PID: {pid} | DNS connections: {count}",
                    pid=pid, process_name=pname or "",
                    mitre_id="T1048.003",
                ))
        except (psutil.AccessDenied, PermissionError):
            pass

        return findings

    @staticmethod
    def _get_process_name(pid: int) -> str:
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"PID:{pid}"
