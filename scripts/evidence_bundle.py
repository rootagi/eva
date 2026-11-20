#!/usr/bin/env python3
"""Create and verify tamper-evident evidence bundles for Eva incident response (compatibility wrapper)."""

import sys

from eva.security_tools.bundle import bundle_main

if __name__ == "__main__":
    sys.exit(bundle_main())
