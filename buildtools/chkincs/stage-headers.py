#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Red Hat, Inc.

"""
Headers staging script for DPDK build system.
"""

import sys
import os
import shutil
from pathlib import Path

def main():
    if len(sys.argv) < 4:
        print("Usage: stage-headers.py <staging_dir> <meson_stamp> [headers...]")
        sys.exit(1)

    staging_dir = Path(sys.argv[1])
    meson_stamp = Path(sys.argv[2])
    headers = sys.argv[3:]

    staging_dir.mkdir(parents=True, exist_ok=True)

    for header in headers:
        file = Path(header)
        shutil.copy2(file, staging_dir / file.name)

    meson_stamp.touch()

if __name__ == "__main__":
    main()
