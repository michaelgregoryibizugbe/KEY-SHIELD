"""
Threat Intelligence Database v3.0
Refined keywords, platform tags, reduced false positives.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Set


class ThreatLevel(Enum):
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatCategory(Enum):
    KEYLOGGER = "KEYLOGGER"
    INPUT_HOOK = "INPUT_HOOK"
    CLIPBOARD_HIJACK = "CLIPBOARD_HIJACK"
    SCREEN_CAPTURE = "SCREEN_CAPTURE"
    DLL_INJECTION = "DLL_INJECTION"
    SO_INJECTION = "SO_INJECTION"
    NETWORK_EXFILTRATION = "NETWORK_EXFILTRATION"
    PERSISTENCE = "PERSISTENCE"
    MEMORY_THREAT = "MEMORY_THREAT"
    PROCESS_ANOMALY = "PROCESS_ANOMALY"
    INPUT_DEVICE_ACCESS = "INPUT_DEVICE_ACCESS"
    PTRACE_INJECTION = "PTRACE_INJECTION"
    LD_PRELOAD = "LD_PRELOAD"
    KERNEL_MODULE = "KERNEL_MODULE"
    USB_HID = "USB_HID"
    SCHEDULED_TASK = "SCHEDULED_TASK"


@dataclass
class ThreatSignature:
    name: str
    category: ThreatCategory
    level: ThreatLevel
    description: str
    indicators: List[str] = field(default_factory=list)
    mitre_id: str = ""
    platforms: List[str] = field(default_factory=lambda: ["windows", "linux", "darwin"])


# ==========================================================
# KNOWN KEYLOGGER PROCESSES
# ==========================================================
KNOWN_KEYLOGGER_PROCESSES: Dict[str, ThreatSignature] = {
    "ardamax": ThreatSignature(
        name="Ardamax Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Commercial keylogger often used maliciously",
        indicators=["ardamax", "akl.exe", "ardamax_keylogger"],
        mitre_id="T1056.001", platforms=["windows"],
    ),
    "revealer": ThreatSignature(
        name="Revealer Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Keystroke logging software",
        indicators=["revealer_keylogger", "rvlkl"],
        mitre_id="T1056.001", platforms=["windows"],
    ),
    "spyrix": ThreatSignature(
        name="Spyrix Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Commercial spyware with keylogging capabilities",
        indicators=["spyrix", "spr_keylogger"],
        mitre_id="T1056.001", platforms=["windows"],
    ),
    "refog": ThreatSignature(
        name="REFOG Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Employee/parental monitoring keylogger",
        indicators=["refog", "mpk.exe", "refog_personal_monitor"],
        mitre_id="T1056.001", platforms=["windows"],
    ),
    "wolfeye": ThreatSignature(
        name="Wolfeye Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.HIGH,
        description="Remote monitoring keylogger",
        indicators=["wolfeye", "we_monitor"],
        mitre_id="T1056.001", platforms=["windows"],
    ),
    "elite_keylogger": ThreatSignature(
        name="Elite Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Advanced commercial keylogger",
        indicators=["elite_keylogger", "elitekeylogger"],
        mitre_id="T1056.001", platforms=["windows"],
    ),
    "hawkeye": ThreatSignature(
        name="HawkEye Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Malware-as-a-service keylogger",
        indicators=["hawkeye_keylogger", "hawk_eye_reborn"],
        mitre_id="T1056.001",
    ),
    "snake_keylogger": ThreatSignature(
        name="Snake Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Info-stealer with keylogging module",
        indicators=["snake_keylogger", "snakekeylogger"],
        mitre_id="T1056.001",
    ),
    "agent_tesla": ThreatSignature(
        name="Agent Tesla", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="RAT/Keylogger widely distributed via phishing",
        indicators=["agent_tesla", "agenttesla"],
        mitre_id="T1056.001",
    ),
    "formbook": ThreatSignature(
        name="FormBook / XLoader", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Info-stealer with form-grabbing and keylogging",
        indicators=["formbook", "xloader"],
        mitre_id="T1056.001",
    ),
    "logkeys": ThreatSignature(
        name="logkeys", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.CRITICAL,
        description="Linux kernel-level keylogger",
        indicators=["logkeys"],
        mitre_id="T1056.001", platforms=["linux"],
    ),
    "pynput_keylog": ThreatSignature(
        name="pynput-based Keylogger", category=ThreatCategory.KEYLOGGER,
        level=ThreatLevel.HIGH,
        description="Python-based keylogger using pynput library",
        indicators=["pynput.keyboard"],
        mitre_id="T1056.001",
    ),
}

# ==========================================================
# SUSPICIOUS KEYWORDS (v3.0 — refined to reduce false positives)
# Now uses compound/specific terms only
# ==========================================================
SUSPICIOUS_PROCESS_KEYWORDS: List[str] = [
    # Specific keylogger terms
    "keylog", "klog", "keystroke", "keysniff", "keycapture",
    "inputcapture", "keyhook", "kbhook", "key_record",
    # Specific spy/surveillance terms
    "screenspy", "clipspy", "clipgrab",
    "ratclient", "backdoor", "trojan", "stealer",
    "cred_dump", "mimikatz", "lazagne",
    # Specific capture/intercept terms
    "keysniff", "inputgrab", "inputrecord",
]

# Separate list of WEAKER indicators that need 2+ matches
WEAK_SUSPICIOUS_KEYWORDS: List[str] = [
    "spy", "sniff", "intercept", "surveillance",
    "hook", "inject", "capture", "recorder",
    "credential", "grabber", "dumper",
]

# ==========================================================
# DLLs / SOs
# ==========================================================
KNOWN_MALICIOUS_DLLS: List[str] = [
    "mhook.dll", "easyhook.dll", "deviare.dll",
    "hookshark.dll", "apihook.dll", "madcodehook.dll",
    "mindshook.dll", "detoured.dll",
]

KNOWN_MALICIOUS_SOS: List[str] = [
    "libkeylogger.so", "libinject.so", "libhook.so",
    "libspy.so", "libcapture.so", "libsniff.so",
    "libptrace_inject.so", "libpreload_hook.so",
]

SYSTEM_DLLS_WHITELIST: Set[str] = {
    "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
    "gdi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
    "msvcrt.dll", "ws2_32.dll", "crypt32.dll", "secur32.dll",
    "comctl32.dll", "comdlg32.dll", "shlwapi.dll", "rpcrt4.dll",
    "imm32.dll", "winmm.dll", "version.dll", "setupapi.dll",
    "cfgmgr32.dll", "bcrypt.dll", "ncrypt.dll", "msvcp_win.dll",
    "ucrtbase.dll", "kernelbase.dll", "mscoree.dll", "clr.dll",
}

SYSTEM_SO_WHITELIST: Set[str] = {
    "libc.so", "libpthread.so", "libdl.so", "libm.so",
    "librt.so", "libgcc_s.so", "libstdc++.so", "ld-linux",
    "libX11.so", "libXext.so", "libGL.so", "libEGL.so",
    "libwayland", "libglib", "libgobject", "libgio",
    "libgtk", "libgdk", "libcairo", "libpango",
    "libsystemd.so", "libnss", "libresolv.so",
}

# ==========================================================
# PERSISTENCE
# ==========================================================
PERSISTENCE_REGISTRY_KEYS: List[str] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    r"SYSTEM\CurrentControlSet\Services",
]

PERSISTENCE_PATHS_LINUX: List[str] = [
    "/etc/rc.local",
    "/etc/crontab",
    "/etc/init.d/",
    "/etc/systemd/system/",
    "~/.config/autostart/",
    "/var/spool/cron/",
    "/var/spool/cron/crontabs/",
    "/etc/xdg/autostart/",
    "/etc/ld.so.preload",
]

PERSISTENCE_PATHS_MACOS: List[str] = [
    "~/Library/LaunchAgents/",
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
]

# ==========================================================
# NETWORK
# ==========================================================
SUSPICIOUS_PORTS: List[int] = [
    4444,    # Metasploit default
    5555,    # Common RAT
    1337,    # Common backdoor
    31337,   # Back Orifice
    12345,   # NetBus
    6666, 6667,  # IRC C2
    9001, 9050, 9150,  # Tor
    4443,    # Common C2
    5900, 5901,  # VNC
]

# Ports flagged only in combination with suspicious process names
SUSPICIOUS_PORTS_CONTEXTUAL: List[int] = [
    8080, 8443,  # Common dev ports — only flag if process is suspicious
    3389,        # RDP — only flag if unexpected
]

SUSPICIOUS_DOMAINS: List[str] = [
    "pastebin.com", "hastebin.com", "transfer.sh",
    "file.io", "0x0.st", "ngrok.io",
    "serveo.net", "localhost.run",
    "duckdns.org", "no-ip.com", "dynu.com",
]

KEYLOG_OUTPUT_PATTERNS: List[str] = [
    "keylog", "keystroke", "typed_keys", "captured_keys",
    "input_log", "key_capture", "kl_output", "keyboard_log",
    "pressed_keys", "key_record",
]

# ==========================================================
# KNOWN MALICIOUS KERNEL MODULES (Linux)
# ==========================================================
SUSPICIOUS_KERNEL_MODULES: List[str] = [
    "diamorphine", "reptile", "suterusu", "knark",
    "adore", "enyelkm", "azazel", "jynx", "jynx2",
    "bdvl", "brokep", "nuk3gh0st", "kovid",
    "keylogger", "rootkit", "hiding",
]
