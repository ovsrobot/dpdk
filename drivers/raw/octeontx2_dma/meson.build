# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.
#

if not is_linux or not dpdk_conf.get('RTE_ARCH_64')
	build = false
	reason = 'only supported on 64-bit Linux'
	subdir_done()
endif

deps += ['bus_pci', 'common_octeontx2', 'rawdev']
sources = files('otx2_dpi_rawdev.c', 'otx2_dpi_msg.c', 'otx2_dpi_test.c')

extra_flags = []

foreach flag: extra_flags
	if cc.has_argument(flag)
		cflags += flag
	endif
endforeach
