"""
Kernel Module Detector — scans for rootkit kernel modules (Linux).
"""

import os
import platform
import subprocess
from typing import List

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import ThreatLevel, ThreatCategory, SUSPICIOUS_KERNEL_MODULES


class KernelModuleDetector(BaseDetector):
    NAME = "KernelModuleDetector"

    def scan(self, quick: bool = False) -> List[Finding]:
        if platform.system() != "Linux":
            return []

        findings = []
        findings.extend(self._scan_loaded_modules())

        if not quick:
            findings.extend(self._check_hidden_modules())
            findings.extend(self._check_tainted_kernel())

        return findings

    def _scan_loaded_modules(self) -> List[Finding]:
        """Check /proc/modules for known malicious kernel modules."""
        findings = []
        modules_file = "/proc/modules"

        if not os.path.exists(modules_file):
            return findings

        try:
            with open(modules_file, "r") as f:
                for line in f:
                    module_name = line.split()[0].lower()

                    for suspicious in SUSPICIOUS_KERNEL_MODULES:
                        if suspicious in module_name:
                            findings.append(Finding(
                                detector=self.NAME,
                                category=ThreatCategory.KERNEL_MODULE,
                                level=ThreatLevel.CRITICAL,
                                title=f"Malicious Kernel Module: {module_name}",
                                description=(
                                    f"Known rootkit kernel module '{module_name}' "
                                    f"is loaded (matches '{suspicious}')."
                                ),
                                evidence=f"Module: {module_name} | Source: /proc/modules",
                                recommendation=(
                                    f"Remove immediately: sudo rmmod {module_name} && "
                                    f"sudo modprobe -r {module_name}"
                                ),
                                mitre_id="T1014",
                            ))
        except (PermissionError, OSError):
            pass

        return findings

    def _check_hidden_modules(self) -> List[Finding]:
        """Compare lsmod output with /proc/modules to detect hidden modules."""
        findings = []

        try:
            # Get modules from /proc/modules
            proc_modules = set()
            with open("/proc/modules", "r") as f:
                for line in f:
                    proc_modules.add(line.split()[0])

            # Get modules from lsmod
            result = subprocess.run(
                ["lsmod"], capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return findings

            lsmod_modules = set()
            for line in result.stdout.strip().split("\n")[1:]:  # Skip header
                parts = line.split()
                if parts:
                    lsmod_modules.add(parts[0])

            # Modules in /proc but not in lsmod = potentially hidden
            hidden = proc_modules - lsmod_modules
            for mod in hidden:
                if mod in ("Module",):  # Skip header artifacts
                    continue
                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.KERNEL_MODULE,
                    level=ThreatLevel.HIGH,
                    title=f"Hidden Kernel Module: {mod}",
                    description="Module in /proc/modules but not in lsmod output.",
                    evidence=f"Module: {mod}",
                    recommendation="Investigate — rootkits often hide from lsmod.",
                    mitre_id="T1014",
                ))

        except (PermissionError, OSError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return findings

    def _check_tainted_kernel(self) -> List[Finding]:
        """Check if kernel is tainted (out-of-tree modules loaded)."""
        findings = []
        taint_file = "/proc/sys/kernel/tainted"

        try:
            with open(taint_file) as f:
                taint_value = int(f.read().strip())

            # Bit 0: proprietary module, Bit 12: unsigned module
            if taint_value & (1 << 12):  # Unsigned module
                # Check if it's likely just VirtualBox (very common false positive)
                level = ThreatLevel.MEDIUM
                vbox_present = False
                try:
                    with open("/proc/modules", "r") as f:
                        if "vbox" in f.read().lower():
                            vbox_present = True
                            level = ThreatLevel.LOW
                except Exception:
                    pass

                findings.append(Finding(
                    detector=self.NAME,
                    category=ThreatCategory.KERNEL_MODULE,
                    level=level,
                    title="Unsigned Kernel Module Loaded",
                    description=f"Kernel taint value: {taint_value} (unsigned module flag set).{' Likely VirtualBox.' if vbox_present else ''}",
                    evidence=f"Taint: {taint_value}",
                    recommendation="Review loaded modules for unauthorized unsigned code.",
                    mitre_id="T1014",
                ))

        except (PermissionError, OSError, ValueError):
            pass

        return findings
