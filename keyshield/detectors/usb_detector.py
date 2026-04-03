"""
USB HID Detector — detects suspicious USB HID devices (BadUSB, Rubber Ducky).
"""

import os
import platform
import subprocess
from typing import List

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import ThreatLevel, ThreatCategory


class USBDetector(BaseDetector):
    NAME = "USBDetector"

    # Known BadUSB vendor/product ID patterns
    BAD_USB_INDICATORS = [
        ("2341", "8036"),   # Arduino Leonardo (common BadUSB platform)
        ("2341", "8037"),   # Arduino Micro
        ("1b4f", "9205"),   # SparkFun Pro Micro
        ("1b4f", "9206"),   # SparkFun Pro Micro
        ("16c0", "0486"),   # Teensy (common attack platform)
        ("feed", "1307"),   # Hak5 Rubber Ducky
        ("04d8", "f2f7"),   # O.MG Cable
    ]

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []
        system = platform.system()

        if system == "Linux":
            findings.extend(self._scan_linux_usb())
        elif system == "Windows":
            findings.extend(self._scan_windows_usb())

        if not quick:
            findings.extend(self._detect_multiple_keyboards())

        return findings

    def _scan_linux_usb(self) -> List[Finding]:
        findings = []

        # Check /sys/bus/usb/devices/
        usb_path = "/sys/bus/usb/devices/"
        if not os.path.isdir(usb_path):
            return findings

        try:
            for device in os.listdir(usb_path):
                dev_path = os.path.join(usb_path, device)

                vendor_file = os.path.join(dev_path, "idVendor")
                product_file = os.path.join(dev_path, "idProduct")
                product_name_file = os.path.join(dev_path, "product")

                if not os.path.exists(vendor_file):
                    continue

                try:
                    with open(vendor_file) as f:
                        vendor_id = f.read().strip()
                    with open(product_file) as f:
                        product_id = f.read().strip()
                except (OSError, PermissionError):
                    continue

                product_name = ""
                try:
                    with open(product_name_file) as f:
                        product_name = f.read().strip()
                except (OSError, PermissionError):
                    pass

                for bad_vendor, bad_product in self.BAD_USB_INDICATORS:
                    if vendor_id == bad_vendor and product_id == bad_product:
                        findings.append(Finding(
                            detector=self.NAME,
                            category=ThreatCategory.USB_HID,
                            level=ThreatLevel.HIGH,
                            title=f"Suspicious USB HID: {product_name or device}",
                            description=(
                                f"USB device matches known BadUSB/attack platform. "
                                f"Vendor: {vendor_id} Product: {product_id}"
                            ),
                            evidence=(
                                f"Device: {device} | VID:PID = {vendor_id}:{product_id} "
                                f"| Name: {product_name}"
                            ),
                            recommendation="Disconnect and investigate this USB device.",
                            mitre_id="T1200",
                        ))

        except (PermissionError, OSError):
            pass

        return findings

    def _scan_windows_usb(self) -> List[Finding]:
        findings = []

        try:
            import subprocess
            result = subprocess.run(
                ["wmic", "path", "Win32_USBControllerDevice", "get", "Dependent"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return findings

            for line in result.stdout.strip().split("\n"):
                line_lower = line.lower()
                for bad_vendor, bad_product in self.BAD_USB_INDICATORS:
                    vid_str = f"vid_{bad_vendor}"
                    pid_str = f"pid_{bad_product}"
                    if vid_str in line_lower and pid_str in line_lower:
                        findings.append(Finding(
                            detector=self.NAME,
                            category=ThreatCategory.USB_HID,
                            level=ThreatLevel.HIGH,
                            title="Suspicious USB HID Device",
                            description=f"Matches BadUSB pattern VID:{bad_vendor} PID:{bad_product}.",
                            evidence=f"Device: {line.strip()[:200]}",
                            recommendation="Disconnect and investigate.",
                            mitre_id="T1200",
                        ))

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return findings

    def _detect_multiple_keyboards(self) -> List[Finding]:
        """Flag if more than expected number of keyboard devices exist."""
        findings = []

        if platform.system() == "Linux":
            try:
                result = subprocess.run(
                    ["cat", "/proc/bus/input/devices"],
                    capture_output=True, text=True, timeout=5,
                )
                keyboard_count = result.stdout.lower().count("keyboard")

                if keyboard_count > 2:  # Most systems have 1-2
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.USB_HID,
                        level=ThreatLevel.MEDIUM,
                        title=f"Multiple Keyboards Detected ({keyboard_count})",
                        description="More keyboard devices than expected — possible HID attack device.",
                        evidence=f"Keyboard input devices: {keyboard_count}",
                        recommendation="Check for unauthorized USB keyboard/HID devices.",
                        mitre_id="T1200",
                    ))

            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

        return findings
