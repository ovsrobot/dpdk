# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation

if is_windows
    subdir_done()
endif

deps += ['bus_pci']
cflags += '-mavx2' # all platforms with idxd HW support AVX
sources = files(
        'idxd_bus.c',
        'idxd_common.c',
        'idxd_pci.c'
)
