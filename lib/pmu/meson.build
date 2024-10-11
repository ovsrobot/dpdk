# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2024 Marvell International Ltd.

headers = files('rte_pmu.h')

if not is_linux
    subdir_done()
endif

sources = files('rte_pmu.c')

indirect_headers += files(
        'rte_pmu_pmc_arm64.h',
)

if dpdk_conf.has('RTE_ARCH_ARM64')
    sources += files('pmu_arm64.c')
endif

deps += ['log']
