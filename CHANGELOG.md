# 📋 Changelog

All notable changes to KeyShield are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [3.0.0] — 2024-12-15

### 🚀 Added

- **Configuration System** — `~/.keyshield/config.json` with whitelist and profiles
- **Self-Exclusion** — KeyShield never flags its own processes
- **Finding Deduplication** — no more duplicate alerts for the same issue
- **Kernel Module Detector** — scans for rootkit kernel modules (Linux)
- **USB HID Detector** — detects BadUSB, Rubber Ducky, O.MG Cable devices
- **Scheduled Task Detector** — Windows Task Scheduler + Linux cron analysis
- **BaseDetector Class** — shared self-exclusion logic for all detectors
- **Tiered Keyword Matching** — strong vs weak keywords reduce false positives
- **SSE Real-Time Progress** — Server-Sent Events replace polling in web GUI
- **CSV Report Export** — export findings as CSV for spreadsheet analysis
- **Scan Profiles** — quick, standard, paranoid configurations
- **Process Whitelist** — configurable list of trusted processes
- **Deterministic Secret Key** — web sessions survive restarts
- **History Limit** — capped at 50 to prevent memory leaks

### 🐛 Fixed

- **Self-detection bug** — KeyShield no longer flags itself as suspicious
- **Thread race condition** — web app scan state protected with `threading.Lock`
- **Path traversal vulnerability** — report download endpoint now sanitized
- **Windows clipboard CF_TEXT** — changed to CF_UNICODETEXT for proper Unicode
- **"import" false positive** — removed from screen capture indicators
- **"obs" false positive** — replaced with "obs-studio", "obs64"
- **Generic keywords** — removed "monitor", "logger", "capture" from strong list
- **cpu_percent always 0** — removed unreliable non-blocking CPU check
- **psutil.users() crash** — wrapped in try/except for headless systems
- **LOG_DIR relative path** — now uses `~/.keyshield/` for reliable paths
- **Unbounded history** — `_scan_history` capped at 50 entries
- **Unused imports** — removed `subprocess` and `SUSPICIOUS_LINUX_APIS`
- **Port 8080 false positive** — moved to contextual ports (only flags if suspicious process)
- **Duplicate findings** — same PID flagged for port AND keyword now deduplicated
- **Signature + keyword double flag** — same process flagged by both scanners deduplicated
- **`~/.bashrc` false positive** — persistence detector no longer flags comment strings

### ♻️ Changed

- All detectors now inherit from `BaseDetector`
- Keyword matching split into `SUSPICIOUS_PROCESS_KEYWORDS` (strong) and `WEAK_SUSPICIOUS_KEYWORDS` (need 2+ matches)
- Web GUI polling replaced with SSE (with polling fallback)
- `REPORTS_DIR` and `LOG_DIR` use `~/.keyshield/` instead of relative paths
- `SUSPICIOUS_PORTS` split into hard and contextual lists
- Version bumped to 3.0.0

## [2.0.0] — 2024-12-14

### Added

- **Web GUI** — Flask-based dashboard with real-time scan progress
- **Cross-platform Hook Detector** — Linux: LD_PRELOAD, ptrace, xinput, /dev/input
- **Cross-platform Screen Capture** — Linux framebuffer detection
- **Linux SO Injection** — /proc/maps analysis for malicious shared objects
- **Linux Keylogger Signatures** — logkeys, lkl, xinput, pynput
- **New Threat Categories** — SO_INJECTION, PTRACE_INJECTION, LD_PRELOAD
- **Progress Callbacks** — engine supports progress reporting for GUI
- **Per-detector Result Counts** — track findings per detector
- **`--web` CLI Flag** — auto-launches browser
- **Auto-browser Opening** — web GUI opens automatically on start
- **SSE-ready Architecture** — prepared for real-time updates

### Changed

- Hook Detector now runs on both Windows and Linux
- Screen Capture Detector now runs on both Windows and Linux
- DLL Injection Detector now handles both DLLs (Win) and SOs (Linux)
- All detectors registered unconditionally (platform checks internal)
- Version bumped to 2.0.0

## [1.0.0] — 2024-12-13

### Added

- Initial release
- 9 detection modules
- CLI interface
- JSON and TXT report generation
- MITRE ATT&CK mapping
- Cross-platform process analysis
- Known keylogger signature database
- Network exfiltration detection
- Persistence mechanism scanning
- Memory anomaly detection
