# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

extra_flags = []

foreach flag: extra_flags
    if cc.has_argument(flag)
        cflags += flag
    endif
endforeach

sources = files('memtank.c',
       'misc.c',
)
headers = files(
        'rte_memtank.h',
)
deps += ['ring', 'telemetry']
