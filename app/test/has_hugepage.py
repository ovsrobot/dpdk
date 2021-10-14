# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 Microsoft Corporation
"""This script checks if the system supports huge pages"""

import platform
import ctypes

osName = platform.system()
if osName == "Linux":
    with open("/proc/sys/vm/nr_hugepages") as file_o:
        content = file_o.read()
        print(content)
elif osName == "FreeBSD":
    # Assume FreeBSD always has hugepages enabled
    print("1")
elif osName == "Windows":
    # On Windows, determine if large page is supported based on the
    # value returned by GetLargePageMinimum. If the return value is zero,
    # the processor does not support large pages.
    if ctypes.windll.kernel32.GetLargePageMinimum() > 0:
        print("1")
    else:
        print("0")
else:
    print("0")
