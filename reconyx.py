#!/usr/bin/env python3
"""
RECONYX — Advanced Bug Bounty Reconnaissance Framework
Entry point script.

Usage:
    python3 reconyx.py -d example.com
    python3 reconyx.py --help
    python3 reconyx.py  (interactive menu)
"""

import sys

# Ensure Python 3.11+
if sys.version_info < (3, 11):
    print(
        "RECONYX requires Python 3.11 or higher.\n"
        f"You are running Python {sys.version_info.major}.{sys.version_info.minor}.\n"
        "Please upgrade: https://www.python.org/downloads/"
    )
    sys.exit(1)

from reconyx.cli import main

if __name__ == "__main__":
    main()
