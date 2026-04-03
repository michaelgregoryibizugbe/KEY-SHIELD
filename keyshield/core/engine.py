"""
Core Scanning Engine v3.0
- Self-exclusion
- Finding deduplication
- Progress callbacks
- Scan profiles
"""

import os
import time
import platform
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Set, Tuple
from datetime import datetime, timezone

from .threat_db import ThreatLevel, ThreatCategory
from .config import get_config
from ..utils.logger import SecurityLogger
from ..utils.system_info import get_system_info


@dataclass
class Finding:
    detector: str
    category: ThreatCategory
    level: ThreatLevel
    title: str
    description: str
    evidence: str = ""
    pid: Optional[int] = None
    process_name: str = ""
    recommendation: str = ""
    mitre_id: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def dedup_key(self) -> Tuple:
        """Key for deduplication."""
        return (self.pid, self.title)

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "category": self.category.value,
            "level": self.level.name,
            "level_value": self.level.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "pid": self.pid,
            "process_name": self.process_name,
            "recommendation": self.recommendation,
            "mitre_id": self.mitre_id,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    scan_id: str = ""
    scan_profile: str = "standard"
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    system_info: Dict = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_risk: ThreatLevel = ThreatLevel.CLEAN
    detectors_run: List[str] = field(default_factory=list)
    detector_results: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def calculate_stats(self):
        self.total_findings = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.level == ThreatLevel.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.level == ThreatLevel.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.level == ThreatLevel.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.level == ThreatLevel.LOW)

        if self.critical_count > 0:
            self.overall_risk = ThreatLevel.CRITICAL
        elif self.high_count > 0:
            self.overall_risk = ThreatLevel.HIGH
        elif self.medium_count > 0:
            self.overall_risk = ThreatLevel.MEDIUM
        elif self.low_count > 0:
            self.overall_risk = ThreatLevel.LOW
        else:
            self.overall_risk = ThreatLevel.CLEAN

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "scan_profile": self.scan_profile,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "system_info": self.system_info,
            "overall_risk": self.overall_risk.name,
            "overall_risk_value": self.overall_risk.value,
            "total_findings": self.total_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "detectors_run": self.detectors_run,
            "detector_results": self.detector_results,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }


class ScanEngine:
    def __init__(self):
        self.logger = SecurityLogger(name="KeyShield.Engine")
        self.config = get_config()
        self.detectors = []
        self._register_detectors()

    def _register_detectors(self):
        from ..detectors.keylogger_detector import KeyloggerDetector
        from ..detectors.hook_detector import HookDetector
        from ..detectors.process_detector import ProcessDetector
        from ..detectors.clipboard_monitor import ClipboardMonitor
        from ..detectors.screen_capture_detector import ScreenCaptureDetector
        from ..detectors.network_exfil_detector import NetworkExfilDetector
        from ..detectors.dll_injection_detector import DLLInjectionDetector
        from ..detectors.persistence_detector import PersistenceDetector
        from ..detectors.memory_scanner import MemoryScanner
        from ..detectors.kernel_module_detector import KernelModuleDetector
        from ..detectors.usb_detector import USBDetector
        from ..detectors.scheduled_task_detector import ScheduledTaskDetector

        self.detectors = [
            KeyloggerDetector(),
            HookDetector(),
            ProcessDetector(),
            ClipboardMonitor(),
            ScreenCaptureDetector(),
            NetworkExfilDetector(),
            DLLInjectionDetector(),
            PersistenceDetector(),
            MemoryScanner(),
            KernelModuleDetector(),
            USBDetector(),
            ScheduledTaskDetector(),
        ]

        self.logger.info(
            f"Registered {len(self.detectors)} detectors for {platform.system()}"
        )

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on (pid, title)."""
        seen: Set[Tuple] = set()
        unique = []
        for f in findings:
            key = f.dedup_key()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def run_scan(
        self,
        quick: bool = False,
        profile: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> ScanResult:
        if profile:
            self.config.set_profile(profile)
        elif quick:
            self.config.set_profile("quick")

        result = ScanResult()
        result.scan_id = str(uuid.uuid4())
        result.scan_profile = self.config.profile.name
        result.start_time = datetime.now(timezone.utc).isoformat()
        result.system_info = get_system_info()

        skip_detectors = set(self.config.profile.skip_detectors)
        active_detectors = [
            d for d in self.detectors
            if d.__class__.__name__ not in skip_detectors
        ]
        total = len(active_detectors)
        start = time.time()

        self.logger.info(
            f"Starting {self.config.profile.name} scan [{result.scan_id}] "
            f"({total} detectors)"
        )

        for idx, detector in enumerate(active_detectors):
            detector_name = detector.__class__.__name__

            if progress_callback:
                progress_callback(detector_name, idx, total)

            try:
                self.logger.info(f"Running: {detector_name}")
                is_quick = self.config.profile.quick
                findings = detector.scan(quick=is_quick)
                count = len(findings) if findings else 0

                if findings:
                    result.findings.extend(findings)
                    self.logger.warning(f"{detector_name}: {count} issue(s)")
                else:
                    self.logger.info(f"{detector_name}: Clean ✅")

                result.detectors_run.append(detector_name)
                result.detector_results[detector_name] = count

            except Exception as e:
                error_msg = f"{detector_name} failed: {e}"
                result.errors.append(error_msg)
                result.detector_results[detector_name] = -1
                self.logger.error(error_msg, exc_info=True)

        # Deduplicate findings
        result.findings = self._deduplicate(result.findings)

        result.end_time = datetime.now(timezone.utc).isoformat()
        result.duration_seconds = round(time.time() - start, 2)
        result.calculate_stats()

        if progress_callback:
            progress_callback("Complete", total, total)

        risk_emoji = {
            ThreatLevel.CLEAN: "✅", ThreatLevel.LOW: "🟡",
            ThreatLevel.MEDIUM: "🟠", ThreatLevel.HIGH: "🔴",
            ThreatLevel.CRITICAL: "🚨",
        }
        self.logger.info(
            f"Scan complete in {result.duration_seconds}s — "
            f"Risk: {risk_emoji.get(result.overall_risk, '')} {result.overall_risk.name} — "
            f"Findings: {result.total_findings}"
        )
        return result
