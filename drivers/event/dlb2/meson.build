
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2020 Intel Corporation

sources = files('dlb2.c',
		'dlb2_iface.c',
		'dlb2_xstats.c',
		'pf/dlb2_main.c',
		'pf/dlb2_pf.c',
		'pf/base/dlb2_resource.c',
		'rte_pmd_dlb2.c'
)

deps += ['mbuf', 'mempool', 'ring', 'bus_vdev', 'pci', 'bus_pci']
install_headers('rte_pmd_dlb2.h')