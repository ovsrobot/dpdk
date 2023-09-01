# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.

sources = [
        'sssnic_hw.c',
        'sssnic_eventq.c'
]

c_args = cflags
base_lib = static_library('sssnic_base', sources,
	dependencies: [static_rte_eal, static_rte_ethdev, static_rte_bus_pci, static_rte_net],
	c_args: c_args)

base_objs = base_lib.extract_all_objects()
