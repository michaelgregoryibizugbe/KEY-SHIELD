"""Consolidated tests for all detectors."""

import unittest


class TestAllDetectors(unittest.TestCase):
    """Every detector must return a list and not crash."""

    def _test_detector(self, detector_class):
        detector = detector_class()
        result = detector.scan(quick=True)
        self.assertIsInstance(result, list)
        for finding in result:
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.level)

    def test_keylogger_detector(self):
        from keyshield.detectors.keylogger_detector import KeyloggerDetector
        self._test_detector(KeyloggerDetector)

    def test_hook_detector(self):
        from keyshield.detectors.hook_detector import HookDetector
        self._test_detector(HookDetector)

    def test_process_detector(self):
        from keyshield.detectors.process_detector import ProcessDetector
        self._test_detector(ProcessDetector)

    def test_clipboard_monitor(self):
        from keyshield.detectors.clipboard_monitor import ClipboardMonitor
        self._test_detector(ClipboardMonitor)

    def test_screen_capture_detector(self):
        from keyshield.detectors.screen_capture_detector import ScreenCaptureDetector
        self._test_detector(ScreenCaptureDetector)

    def test_network_exfil_detector(self):
        from keyshield.detectors.network_exfil_detector import NetworkExfilDetector
        self._test_detector(NetworkExfilDetector)

    def test_dll_injection_detector(self):
        from keyshield.detectors.dll_injection_detector import DLLInjectionDetector
        self._test_detector(DLLInjectionDetector)

    def test_persistence_detector(self):
        from keyshield.detectors.persistence_detector import PersistenceDetector
        self._test_detector(PersistenceDetector)

    def test_memory_scanner(self):
        from keyshield.detectors.memory_scanner import MemoryScanner
        self._test_detector(MemoryScanner)

    def test_kernel_module_detector(self):
        from keyshield.detectors.kernel_module_detector import KernelModuleDetector
        self._test_detector(KernelModuleDetector)

    def test_usb_detector(self):
        from keyshield.detectors.usb_detector import USBDetector
        self._test_detector(USBDetector)

    def test_scheduled_task_detector(self):
        from keyshield.detectors.scheduled_task_detector import ScheduledTaskDetector
        self._test_detector(ScheduledTaskDetector)


if __name__ == "__main__":
    unittest.main()
