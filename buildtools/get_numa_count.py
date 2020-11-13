#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 PANTHEON.tech s.r.o.

import ctypes
import glob
import os
import subprocess

if os.name == 'posix':
    if os.path.isdir('/sys/devices/system/node'):
        print(len(glob.glob('/sys/devices/system/node/node*')))
    else:
        subprocess.run(['sysctl', '-n', 'vm.ndomains'])

elif os.name == 'nt':
    libkernel32 = ctypes.windll.kernel32

    count = ctypes.c_ulong()

    libkernel32.GetNumaHighestNodeNumber(ctypes.pointer(count))
    print(count.value + 1)
