#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Dmitry Kozlyuk <dmitry.kozliuk@gmail.com>

import os
import subprocess
import sys
import tempfile
import time

_, tmp_root, ar, archive, output, *pmdinfogen = sys.argv
with tempfile.TemporaryDirectory(dir=tmp_root, ignore_cleanup_errors=True) as temp:
    paths = []
    for name in subprocess.run([ar, "t", archive], stdout=subprocess.PIPE,
                               check=True).stdout.decode().splitlines():
        if os.path.exists(name):
            paths.append(name)
        else:
            subprocess.run([ar, "x", os.path.abspath(archive), name],
                           check=True, cwd=temp)
            paths.append(os.path.join(temp, name))
    subprocess.run(pmdinfogen + paths + [output], check=True)

    if os.name == "nt":
        # Instances have been seen on Windows where the temporary directory fails to get cleaned
        # up due to ERROR_SHARING_VIOLATION (32).
        # The sleep below is a mitigation for that issue, while ignore_cleanup_errors=True avoids
        # failures when the issue is hit despite the mitigation.
        time.sleep(1)
