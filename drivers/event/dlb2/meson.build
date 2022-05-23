
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2020 Intel Corporation

if not is_linux or not dpdk_conf.has('RTE_ARCH_X86_64')
        build = false
        reason = 'only supported on x86_64 Linux'
        subdir_done()
endif

sources = files(
        'dlb2.c',
        'dlb2_iface.c',
        'dlb2_xstats.c',
        'pf/dlb2_main.c',
        'pf/dlb2_pf.c',
        'pf/base/dlb2_resource.c',
        'rte_pmd_dlb2.c',
        'dlb2_selftest.c',
)

dlb2_avx512_support = false

if dpdk_conf.has('RTE_ARCH_X86_64')
        dlb2_avx512_support = (
	    cc.get_define('__AVX512VL__', args: machine_args) != ''
	)
endif

if dlb2_avx512_support == true
        sources += files('dlb2_avx512.c')
else
        sources += files('dlb2_sve.c')
endif

headers = files('rte_pmd_dlb2.h')

deps += ['mbuf', 'mempool', 'ring', 'pci', 'bus_pci']
