# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell International Ltd.

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

includes = [global_inc]

sources = files('rte_pmu.c')
headers = files('rte_pmu.h')
