# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell International Ltd.
#

if not is_linux or not dpdk_conf.get('RTE_ARCH_64')
	build = false
	reason = 'only supported on 64-bit Linux'
	subdir_done()
endif

sources = files('cn10k_worker.c',
		'cn10k_eventdev.c',
		'cn9k_worker.c',
		'cn9k_eventdev.c',
		'cnxk_eventdev.c')

deps += ['bus_pci', 'common_cnxk', 'net_cnxk']
