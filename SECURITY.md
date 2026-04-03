# 🔒 Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 3.0.x   | ✅ Active support  |
| 2.0.x   | ⚠️ Security fixes only |
| < 2.0   | ❌ No longer supported |

## Reporting a Vulnerability

If you discover a security vulnerability in KeyShield, please report it
responsibly:

### 📧 Email

Send details to: **keyshield-security@example.com**

### 📝 What to Include

1. **Description** of the vulnerability
2. **Steps to reproduce**
3. **Impact assessment** — what could an attacker do?
4. **Suggested fix** (if you have one)
5. **Your contact information** for follow-up

### ⏱️ Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Within 14 business days |
| Public disclosure | After fix is released |

### 🙏 Recognition

We will credit security researchers in our CHANGELOG and README
(unless you prefer to remain anonymous).

## Security Design Principles

### What KeyShield Does

- ✅ Scans local processes, files, and system configuration
- ✅ Generates reports stored locally
- ✅ Runs a local-only web server (127.0.0.1 by default)

### What KeyShield Does NOT Do

- ❌ **No network telemetry** — never phones home
- ❌ **No data collection** — all data stays on your machine
- ❌ **No cloud dependencies** — works fully offline
- ❌ **No keystroke capture** — KeyShield detects keyloggers, it is not one
- ❌ **No persistent system modifications** — config stored in `~/.keyshield/`

## Web GUI Security

- Binds to `127.0.0.1` by default (localhost only)
- Path traversal protection on report downloads
- Thread-safe state management with proper locking
- No authentication by default (local-only use)

> ⚠️ **If binding to `0.0.0.0`**, the web GUI will be accessible from the network.
> Use this only in trusted environments and consider adding authentication.

## Responsible Disclosure

We follow a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. We acknowledge and begin investigation
3. We develop and test a fix
4. We release the fix and update CHANGELOG
5. We credit the reporter (with permission)
6. Reporter may publish details after fix release

## Ethics

KeyShield is a **defensive security tool**. We ask that all contributors
and users:

- Use KeyShield only for **authorized security testing**
- Never use KeyShield code to create **offensive tools**
- Report vulnerabilities **responsibly**
- Follow all applicable **laws and regulations**
