#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Dmitry Kozlyuk <dmitry.kozliuk@gmail.com>

import os
import subprocess
import sys
import tempfile

_, tmp_root, archiver, archive, output, *pmdinfogen = sys.argv
with tempfile.TemporaryDirectory(dir=tmp_root) as temp:
    paths = []
    if archiver == 'lib':
        archiver_options = ['/LIST', '/NOLOGO']
    else:
        archiver_options = ['t']
    for name in subprocess.run([archiver] + archiver_options + [archive], stdout=subprocess.PIPE,
                               check=True).stdout.decode().splitlines():
        if os.path.exists(name):
            paths.append(name)
        else:
            subprocess.run([archiver, "x", os.path.abspath(archive), name],
                           check=True, cwd=temp)
            paths.append(os.path.join(temp, name))
    subprocess.run(pmdinfogen + paths + [output], check=True)
