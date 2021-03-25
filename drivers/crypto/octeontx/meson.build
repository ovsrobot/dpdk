# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Cavium, Inc
#

if not is_linux or not dpdk_conf.get('RTE_ARCH_64')
	build = false
	reason = 'only supported on 64-bit Linux'
	subdir_done()
endif

deps += ['bus_pci']
deps += ['common_cpt']

sources = files('otx_cryptodev.c',
		'otx_cryptodev_capabilities.c',
		'otx_cryptodev_hw_access.c',
		'otx_cryptodev_mbox.c',
		'otx_cryptodev_ops.c')

includes += include_directories('../../common/cpt')
