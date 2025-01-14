# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Cavium, Inc

std_deps = ['eal']
drivers = [
        'cpt',
        'dpaax',
        'iavf',
        'idpf',
        'ionic',
        'mvep',
        'octeontx',
]

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
