#!/usr/bin/env python3
"""Validate Eva endpoint triage reports (compatibility wrapper)."""

import sys

from eva.security_tools.triage import validator_main

if __name__ == "__main__":
    sys.exit(validator_main())
