# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Corigine, Inc.

if not is_linux or not dpdk_conf.get('RTE_ARCH_64')
    build = false
    reason = 'only supported on 64-bit Linux'
endif

sources = files(
        'nfp_common.c',
        'nfp_common_log.c',
        'nfp_common_pci.c',
        'nfp_dev.c',
)

deps += ['bus_pci', 'net']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
