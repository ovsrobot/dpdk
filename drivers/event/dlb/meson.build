# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2020 Intel Corporation

sources = files('dlb.c',
		'dlb_iface.c',
		'dlb_xstats.c',
		'rte_pmd_dlb.c',
		'dlb_selftest.c',
		'pf/dlb_pf.c',
		'pf/dlb_main.c',
		'pf/base/dlb_resource.c'
)

allow_experimental_apis = true
deps += ['mbuf', 'mempool', 'ring', 'pci', 'bus_pci']
install_headers('rte_pmd_dlb.h')
