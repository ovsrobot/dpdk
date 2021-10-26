#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Dmitry Kozlyuk <dmitry.kozliuk@gmail.com>

import os
import subprocess
import sys
import tempfile

_, tmp_root, ar, archive, output, *pmdinfogen = sys.argv
archive = os.path.abspath(archive)
names = subprocess.run([ar, "t", archive],
    stdout=subprocess.PIPE, check=True).stdout.decode().splitlines()
with open(archive, "rb") as f:
    is_thin = f.read(7) == b"!<thin>"
if is_thin:
    # Thin archive needs no unpacking, just use the paths within.
    paths = [os.path.join(archive, name) for name in names]
    subprocess.run(pmdinfogen + paths + [output], check=True)
else:
    with tempfile.TemporaryDirectory(dir=tmp_root) as temp:
        # Don't use "ar p", because its output is corrupted on Windows.
        paths = [os.path.join(temp, name) for name in names]
        subprocess.run([ar, "x", archive], check=True, cwd=temp)
        subprocess.run(pmdinfogen + paths + [output], check=True)
