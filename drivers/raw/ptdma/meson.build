# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021 Advanced Micro Devices, Inc. All rights reserved.

build = dpdk_conf.has('RTE_ARCH_X86')
reason = 'only supported on x86'
sources = files(
	'ptdma_rawdev.c',
	'ptdma_dev.c',
	'ptdma_rawdev_test.c')
deps += ['bus_pci',
	'bus_vdev',
	'mbuf',
	'rawdev']

headers = files('rte_ptdma_rawdev.h',
		'rte_ptdma_rawdev_fns.h')
