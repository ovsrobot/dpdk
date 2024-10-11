# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2024 Marvell International Ltd.

headers = files('rte_pmu.h')

if not is_linux
    subdir_done()
endif

sources = files('rte_pmu.c')

deps += ['log']
