# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

drivers = [
        'bucket',
        'cnxk',
        'dpaa',
        'dpaa2',
        'octeontx',
        'ring',
        'stack',
]

std_deps = ['mempool']

log_prefix = 'mempool'

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
