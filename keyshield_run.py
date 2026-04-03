#!/usr/bin/env python3
"""
KeyShield v3.0 — Direct Run Script
"""

import sys
import os

# Add the current directory to sys.path to allow importing keyshield module
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from keyshield.cli.main import main

if __name__ == "__main__":
    main()
