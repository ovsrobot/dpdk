# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 Microsoft Corporation
"""This script returns the system cpu range"""

import multiprocessing

cpucount = multiprocessing.cpu_count()
if cpucount is None:
    # use fallback cpu count
    print("0-3")
else:
    print("0-" + str(cpucount - 1))
