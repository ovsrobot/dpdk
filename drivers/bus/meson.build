# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

drivers = [
        'auxiliary',
        'cdx',
        'dpaa',
        'fslmc',
        'ifpga',
        'pci',
        'platform',
        'uacce',
        'vdev',
        'vmbus',
]

std_deps = ['eal']

log_prefix = 'bus'

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
