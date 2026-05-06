# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Corigine, Inc.

cflags += [
        '-DSXE2_DPDK_DRIVER',
        '-DSXE2_DPDK_DEBUG',
]

deps += ['bus_pci', 'net', 'eal', 'ethdev']

sources = files(
        'sxe2_common.c',
        'sxe2_common_log.c',
        'sxe2_ioctl_chnl.c',
)
