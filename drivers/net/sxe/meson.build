# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C), 2022, Linkdata Technology Co., Ltd.
cflags += ['-DSXE_DPDK']
cflags += ['-DSXE_HOST_DRIVER']

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
        'pf/sxe_pmd_hdc.c',
        'pf/sxe_phy.c',
        'pf/sxe_ptp.c',
        'pf/sxe_dcb.c',
        'base/sxe_queue_common.c',
	'base/sxe_rx_common.c',
	'base/sxe_tx_common.c',
	'base/sxe_offload_common.c',
        'base/sxe_common.c',
        'base/sxe_hw.c',
)

includes += include_directories('base')
includes += include_directories('pf')
includes += include_directories('include/sxe/')
includes += include_directories('include/')