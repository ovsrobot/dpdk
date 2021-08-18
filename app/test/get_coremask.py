#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 Microsoft Corporation

import multiprocessing

c = multiprocessing.cpu_count()
print("0-"+str(c-1))
