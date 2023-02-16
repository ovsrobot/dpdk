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
indirect_headers += files(
        'rte_pmu_pmc_arm64.h',
)

if dpdk_conf.has('RTE_ARCH_ARM64')
    sources += files('pmu_arm64.c')
endif
