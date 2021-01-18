# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2020 Marvell.
#

sources = files(
               'otx_ep_ethdev.c',
               'otx_ep_vf.c',
               'otx2_ep_vf.c',
               'otx_ep_rxtx.c',
               )

extra_flags = []
# This integrated controller runs only on a arm64 machine, remove 32bit warnings
if not dpdk_conf.get('RTE_ARCH_64')
        extra_flags += ['-Wno-int-to-pointer-cast', '-Wno-pointer-to-int-cast']
endif

foreach flag: extra_flags
        if cc.has_argument(flag)
                cflags += flag
        endif
endforeach

includes += include_directories('../../common/octeontx2')
