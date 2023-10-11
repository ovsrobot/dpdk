# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.
#

sources = files(
        'otx_ep_ethdev.c',
        'otx_ep_rxtx.c',
        'otx_ep_vf.c',
        'otx2_ep_vf.c',
        'cnxk_ep_vf.c',
        'otx_ep_mbox.c',
)

if (toolchain == 'gcc' and cc.version().version_compare('>=11.0.0'))
    error_cflags += ['-Wno-array-bounds']
endif

foreach flag: error_cflags
    if cc.has_argument(flag)
        c_args += flag
    endif
endforeach
