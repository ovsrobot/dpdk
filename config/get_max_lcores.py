#!/usr/bin/python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Arm Limited

import os

max_lcores = []

nCPU = os.cpu_count()

max_lcores.append(str(nCPU & 0xFFF))             # Number of CPUs

print(' '.join(max_lcores))
