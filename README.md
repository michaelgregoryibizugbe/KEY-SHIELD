<div align="center">

<img src="keyshield/web/static/img/shield.svg" alt="KeyShield Logo" width="120" height="140">

# 🛡️ KeyShield v3.0

### All-in-One Input Security Monitor

**Detect keyloggers, rootkits, input hooks, clipboard hijackers, screen capture tools,
DLL/.so injection, BadUSB devices, network exfiltration, and persistence mechanisms.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-0f3460?style=for-the-badge)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-ef4444?style=for-the-badge)](https://attack.mitre.org/)

<br>

[**🚀 Quick Start**](#-quick-start) •
[**🌐 Web GUI**](#-web-gui) •
[**🔍 Detectors**](#-detection-modules) •
[**📖 Docs**](#-documentation) •
[**🤝 Contributing**](CONTRIBUTING.md)

</div>

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/michaelgregoryibizugbe/KEY-SHIELD.git
cd keyshield

# Automated Professional Setup
python3 -m venv venv
./venv/bin/pip install -e .

# Optional: Create global command (Linux/macOS)
sudo ln -sf $(pwd)/kshield /usr/local/bin/kshield
```

### 2. Run your first scan

```bash
# Professional Global Command
sudo kshield scan

# Or via local wrapper
sudo ./kshield scan
```

---

## 🌐 Web GUI

Launch the high-end **Command Center** dashboard:

```bash
sudo kshield web
```

- **Interactive Dashboard:** Real-time system analytics.
- **SSE Progress:** Watch detectors work in real-time.
- **Rule Management:** Manage whitelists and profiles directly.

---

## 💻 CLI Usage

```bash
# Full standard scan
sudo kshield scan

# Quick optimized scan
sudo kshield scan --quick

# Change scan profile
sudo kshield scan --profile paranoid

# Continuous background monitoring
sudo kshield monitor --interval 60
```

---

## 🔍 Detection Modules

KeyShield includes **12 specialized detectors**:

| Category | Detectors |
|---|---|
| **Input** | Keylogger, Hook, Clipboard, USB HID |
| **System** | Process, Persistence, Memory, Kernel Module, Scheduled Task |
| **Data** | Network Exfil, Screen Capture, DLL/SO Injection |

---

## ⚙️ Configuration

KeyShield automatically manages a persistent configuration in your home directory:
`~/.keyshield/config.json`

You can manage the **Process Exclusion List** (Whitelist) and **Scan Profiles** via the Web UI or by editing the JSON file directly.

---

## 🛡️ Pro Tips for Linux

- **Always use `sudo`**: KeyShield requires root privileges to audit system-owned processes and kernel modules.
- **False Positive Filtering**: v3.0 automatically filters ~95% of common Linux noise (kernel threads, browser sandboxes).
- **Reports**: All scan reports are saved to `~/.keyshield/reports/` in JSON, TXT, and CSV formats.

---

<div align="center">

**Made with 🛡️ by the KeyShield Project**

[Report Bug](https://github.com/yourusername/keyshield/issues/new?template=bug_report.md) •
[Security Issue](SECURITY.md)

</div>
