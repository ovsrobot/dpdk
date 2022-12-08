# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 Marvell.

if not is_linux or not dpdk_conf.get('RTE_ARCH_64')
    build = false
    reason = 'only supported on 64-bit Linux'
    subdir_done()
endif

headers = files(
        'ml_utils.h',
        'ml_utils_generic.h',
)

sources = files(
        'ml_utils.c',
        'ml_utils_generic.c',
)

deps += ['mldev']

pmd_supports_disable_iova_as_pa = true
