# 🤝 Contributing to KeyShield

First off, thank you for considering contributing to KeyShield! Every contribution
makes this tool better for the cybersecurity community.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding a New Detector](#adding-a-new-detector)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating,
you are expected to uphold this code.

## How Can I Contribute?

### 🐛 Bug Reports
- Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md)
- Include your OS, Python version, and steps to reproduce

### 💡 Feature Requests
- Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md)
- Explain the use case and expected behavior

### 🔧 Code Contributions
- Fix bugs, add detectors, improve documentation
- All contributions must include tests
- Follow the coding standards below

### 📖 Documentation
- Fix typos, improve explanations, add examples
- Documentation-only PRs are always welcome

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/keyshield.git
cd keyshield

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# 3. Install in development mode
pip install -e ".[dev]"
# or manually:
pip install -e .
pip install pytest pytest-cov flake8 black

# 4. Create a feature branch
git checkout -b feature/my-awesome-detector

# 5. Run tests to make sure everything works
python -m pytest tests/ -v
```

## Project Structure

```
keyshield/
├── core/           # Engine, config, threat database
├── detectors/      # All detection modules
├── utils/          # Logging, reporting, helpers
├── cli/            # Command-line interface
├── web/            # Flask web GUI
└── tests/          # Test suite
```

## Adding a New Detector

This is the most common contribution. Here's the step-by-step process:

### Step 1: Create the Detector

```python
# keyshield/detectors/my_new_detector.py

"""
My New Detector — describe what it detects.
"""

import platform
from typing import List

from .base_detector import BaseDetector
from ..core.engine import Finding
from ..core.threat_db import ThreatLevel, ThreatCategory


class MyNewDetector(BaseDetector):
    """
    Detects XYZ threats via:
    1. Method A
    2. Method B
    """

    NAME = "MyNewDetector"

    def scan(self, quick: bool = False) -> List[Finding]:
        findings = []

        # Always run essential checks
        findings.extend(self._check_essential())

        # Deep checks only on full scan
        if not quick:
            findings.extend(self._check_deep())

        return findings

    def _check_essential(self) -> List[Finding]:
        findings = []

        # Use self.safe_process_iter() — it auto-skips
        # KeyShield's own processes and whitelisted ones
        for proc in self.safe_process_iter(["pid", "name", "cmdline"]):
            try:
                pname = (proc.info["name"] or "").lower()
                pid = proc.info["pid"]

                # Your detection logic here
                if self._is_suspicious(pname):
                    findings.append(Finding(
                        detector=self.NAME,
                        category=ThreatCategory.PROCESS_ANOMALY,
                        level=ThreatLevel.HIGH,
                        title=f"Suspicious: {proc.info['name']}",
                        description="Description of what was found.",
                        evidence=f"PID: {pid} | Name: {pname}",
                        pid=pid,
                        process_name=pname,
                        recommendation="What the user should do.",
                        mitre_id="T1234",  # MITRE ATT&CK ID
                    ))

            except Exception:
                continue

        return findings

    def _check_deep(self) -> List[Finding]:
        # Deeper analysis for full scans
        return []

    def _is_suspicious(self, name: str) -> bool:
        # Your logic
        return False
```

### Step 2: Register the Detector

Add to `keyshield/core/engine.py`:

```python
from ..detectors.my_new_detector import MyNewDetector

# In _register_detectors():
self.detectors.append(MyNewDetector())
```

Add to `keyshield/detectors/__init__.py`:

```python
from .my_new_detector import MyNewDetector
```

### Step 3: Add Tests

```python
# tests/test_detectors.py (add to existing)

def test_my_new_detector():
    from keyshield.detectors.my_new_detector import MyNewDetector
    detector = MyNewDetector()
    result = detector.scan(quick=True)
    assert isinstance(result, list)
```

### Step 4: Update Documentation

- Add detector to the table in `README.md`
- Add detector card to `keyshield/web/templates/scan.html`
- Update `keyshield/web/templates/settings.html`

## Coding Standards

### Style

- **Python**: Follow [PEP 8](https://peps.python.org/pep-0008/)
- **Formatting**: Use `black` with default settings
- **Imports**: Use absolute imports within the package
- **Type hints**: Use them for all function signatures
- **Docstrings**: Required for all classes and public methods

### Naming

- Detectors: `MyThingDetector` in `my_thing_detector.py`
- Methods: `_detect_xyz()` for detection methods, `_check_xyz()` for checks
- Findings: Always include `detector`, `category`, `level`, `title`, `description`

### Error Handling

```python
# Always catch psutil exceptions specifically
try:
    # process operations
except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
    continue

# Never let a detector crash the entire scan
# The engine wraps each detector in try/except
```

### Platform Handling

```python
import platform

def scan(self, quick=False):
    system = platform.system()
    if system == "Windows":
        findings.extend(self._windows_checks())
    elif system == "Linux":
        findings.extend(self._linux_checks())
    elif system == "Darwin":
        findings.extend(self._macos_checks())
```

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=keyshield --cov-report=term-missing

# Lint
flake8 keyshield/ --max-line-length=120 --ignore=E501,W503

# Format
black keyshield/ tests/
```

### Test Requirements

- Every detector must have at least one test
- Tests must not require elevated privileges
- Tests must pass on both Windows and Linux
- Tests must not make network requests
- Tests must complete in < 30 seconds each

## Pull Request Process

1. **Update tests** — all new code must have tests
2. **Run the full test suite** — `python -m pytest tests/ -v`
3. **Update documentation** — README, docstrings, CHANGELOG
4. **Create PR** with the [PR template](.github/PULL_REQUEST_TEMPLATE.md)
5. **Describe your changes** clearly in the PR description
6. **Link any related issues** using `Fixes #123` or `Closes #456`
7. **Wait for review** — maintainers will review within 48 hours

## Reporting Bugs

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:

1. **OS and Python version**
2. **KeyShield version** (`keyshield --version`)
3. **Steps to reproduce**
4. **Expected behavior**
5. **Actual behavior**
6. **Error messages / logs**

## Requesting Features

Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md) and include:

1. **Problem description** — what gap does this fill?
2. **Proposed solution** — how should it work?
3. **Alternatives considered**
4. **MITRE ATT&CK mapping** (if applicable)

---

Thank you for making KeyShield better! 🛡️
