# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Cavium, Inc

if not is_linux or not dpdk_conf.get('RTE_ARCH_64')
    build = false
    reason = 'only supported on 64-bit Linux'
    subdir_done()
endif
if get_option('mbuf_dynfield3_size') != 0
    build = false
    reason = 'requires sizeof(struct rte_mbuf) <= 128'
    subdir_done()
endif

sources = files(
        'octeontx_fpavf.c',
        'rte_mempool_octeontx.c',
)

deps += ['mbuf', 'bus_pci', 'common_octeontx']

require_iova_in_mbuf = false
