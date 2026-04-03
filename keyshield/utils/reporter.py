"""Report Generator v3.0 — robust paths, CSV export."""

import csv
import json
import os
from datetime import datetime
from typing import Optional

from ..core.threat_db import ThreatLevel
from .helpers import get_data_dir


REPORTS_DIR = os.path.join(get_data_dir(), "reports")
try:
    os.makedirs(REPORTS_DIR, exist_ok=True)
except OSError:
    REPORTS_DIR = os.path.join(os.getcwd(), "reports")
    os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportGenerator:

    @staticmethod
    def generate_json_report(result, filepath: Optional[str] = None) -> str:
        if filepath is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(REPORTS_DIR, f"scan_{ts}.json")
        with open(filepath, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        return filepath

    @staticmethod
    def generate_text_report(result, filepath: Optional[str] = None) -> str:
        if filepath is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(REPORTS_DIR, f"scan_{ts}.txt")

        risk_bar = {
            ThreatLevel.CLEAN: "========== CLEAN",
            ThreatLevel.LOW: "========== LOW",
            ThreatLevel.MEDIUM: "======.... MEDIUM",
            ThreatLevel.HIGH: "====...... HIGH",
            ThreatLevel.CRITICAL: "==........ CRITICAL",
        }

        lines = [
            "=" * 60,
            "  KEYSHIELD SECURITY SCAN REPORT",
            "=" * 60, "",
            f"  Scan ID:    {result.scan_id}",
            f"  Profile:    {result.scan_profile}",
            f"  Duration:   {result.duration_seconds}s",
            f"  Risk:       {risk_bar.get(result.overall_risk, 'UNKNOWN')}", "",
            f"  Critical: {result.critical_count}  High: {result.high_count}  "
            f"Medium: {result.medium_count}  Low: {result.low_count}",
            f"  Total:    {result.total_findings}", "",
        ]

        if result.findings:
            lines.append("-" * 60)
            sorted_findings = sorted(result.findings, key=lambda f: f.level.value, reverse=True)
            for i, f in enumerate(sorted_findings, 1):
                lines.extend([
                    f"  [{i}] [{f.level.name}] {f.title}",
                    f"      {f.description}",
                    f"      Evidence: {f.evidence}",
                ])
                if f.recommendation:
                    lines.append(f"      Fix: {f.recommendation}")
                if f.mitre_id:
                    lines.append(f"      MITRE: {f.mitre_id}")
                lines.append("")

        lines.extend(["=" * 60, "  End of Report", "=" * 60])

        with open(filepath, "w") as f:
            f.write("\n".join(lines))
        return filepath

    @staticmethod
    def generate_csv_report(result: ScanResult, filepath: Optional[str] = None) -> str:
        """NEW: Generate CSV report for spreadsheet analysis."""
        if filepath is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(REPORTS_DIR, f"scan_{ts}.csv")

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Severity", "Title", "Category", "Detector",
                "Description", "Evidence", "PID", "Process",
                "MITRE", "Recommendation", "Timestamp",
            ])
            for finding in result.findings:
                writer.writerow([
                    finding.level.name, finding.title, finding.category.value,
                    finding.detector, finding.description, finding.evidence,
                    finding.pid or "", finding.process_name,
                    finding.mitre_id, finding.recommendation, finding.timestamp,
                ])
        return filepath

    @staticmethod
    def print_summary(result: ScanResult):
        BOLD = "\033[1m"
        RESET = "\033[0m"
        risk_colors = {
            ThreatLevel.CLEAN: "\033[32m", ThreatLevel.LOW: "\033[33m",
            ThreatLevel.MEDIUM: "\033[33m", ThreatLevel.HIGH: "\033[31m",
            ThreatLevel.CRITICAL: "\033[41m\033[37m",
        }
        color = risk_colors.get(result.overall_risk, RESET)

        print(f"\n{BOLD}{'=' * 50}{RESET}")
        print(f"{BOLD}  KEYSHIELD SCAN RESULTS{RESET}")
        print(f"{BOLD}{'=' * 50}{RESET}")
        print(f"  Duration: {result.duration_seconds}s | Profile: {result.scan_profile}")
        print(f"  Risk:     {color}{BOLD}{result.overall_risk.name}{RESET}")
        print()

        if result.critical_count:
            print(f"  \033[31mCritical: {result.critical_count}\033[0m")
        if result.high_count:
            print(f"  \033[31mHigh:     {result.high_count}\033[0m")
        if result.medium_count:
            print(f"  \033[33mMedium:   {result.medium_count}\033[0m")
        if result.low_count:
            print(f"  \033[33mLow:      {result.low_count}\033[0m")
        if result.total_findings == 0:
            print(f"  \033[32mNo threats detected!\033[0m")

        print(f"\n  Detectors: {len(result.detectors_run)} | Findings: {result.total_findings}")
        print(f"{BOLD}{'=' * 50}{RESET}\n")
