#!/usr/bin/env python3
"""Run Eva endpoint triage collectors and aggregate their findings (compatibility wrapper)."""

import sys

from eva.security_tools.triage import orchestrator_main

if __name__ == "__main__":
    sys.exit(orchestrator_main())
