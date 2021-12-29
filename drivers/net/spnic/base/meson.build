# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Ramaxel Memory Technology, Ltd

sources = [
	'spnic_eqs.c',
	'spnic_hwdev.c',
	'spnic_hwif.c',
	'spnic_mbox.c',
	'spnic_mgmt.c',
	'spnic_nic_event.c'
]

extra_flags = []
# The driver runs only on arch64 machine, remove 32bit warnings
if not dpdk_conf.get('RTE_ARCH_64')
        extra_flags += ['-Wno-int-to-pointer-cast', '-Wno-pointer-to-int-cast']
endif

foreach flag: extra_flags
        if cc.has_argument(flag)
                cflags += flag
        endif
endforeach

deps += ['hash']
cflags += ['-DHW_CONVERT_ENDIAN']
c_args = cflags

base_lib = static_library('spnic_base', sources,
	dependencies: [static_rte_eal, static_rte_ethdev, static_rte_bus_pci, static_rte_hash],
	c_args: c_args)
base_objs = base_lib.extract_all_objects()
