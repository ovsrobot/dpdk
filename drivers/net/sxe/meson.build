# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C), 2022, Linkdata Technology Co., Ltd.
if not is_linux or not (dpdk_conf.has('RTE_ARCH_X86_64') or dpdk_conf.has('RTE_ARCH_ARM64'))
    build = false
    reason = 'only supported on x86_64 or arm64 Linux'
    subdir_done()
endif

cflags += ['-DSXE_DPDK']
cflags += ['-DSXE_HOST_DRIVER']
cflags += ['-DSXE_DPDK_L4_FEATURES']
cflags += ['-DSXE_DPDK_SRIOV']
cflags += ['-DSXE_DPDK_SIMD']

#subdir('base')
#objs = [base_objs]

deps += ['hash']
sources = files(
        'pf/sxe_main.c',
        'pf/sxe_filter.c',
        'pf/sxe_flow_ctrl.c',
        'pf/sxe_irq.c',
        'pf/sxe_ethdev.c',
        'pf/sxe_offload.c',
        'pf/sxe_queue.c',
        'pf/sxe_rx.c',
        'pf/sxe_tx.c',
        'pf/sxe_stats.c',
        'pf/sxe_pmd_hdc.c',
        'pf/sxe_phy.c',
        'pf/sxe_ptp.c',
        'pf/sxe_vf.c',
        'pf/sxe_dcb.c',
        'vf/sxevf_main.c',
        'vf/sxevf_filter.c',
        'vf/sxevf_irq.c',
        'vf/sxevf_msg.c',
        'vf/sxevf_ethdev.c',
        'vf/sxevf_stats.c',
        'vf/sxevf_rx.c',
        'vf/sxevf_tx.c',
        'vf/sxevf_queue.c',
        'vf/sxevf_offload.c',
        'base/sxe_queue_common.c',
        'base/sxe_rx_common.c',
        'base/sxe_tx_common.c',
        'base/sxe_offload_common.c',
        'base/sxe_common.c',
        'base/sxe_hw.c',
        'base/sxevf_hw.c',
)

testpmd_sources = files('sxe_testpmd.c')

if arch_subdir == 'x86'
    sources += files('pf/sxe_vec_sse.c')
elif arch_subdir == 'arm'
    sources += files('pf/sxe_vec_neon.c')
endif

includes += include_directories('base')
includes += include_directories('pf')
includes += include_directories('vf')
includes += include_directories('include/sxe/')
includes += include_directories('include/')
