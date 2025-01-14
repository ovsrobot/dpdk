# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

if is_windows
    subdir_done()
endif

drivers = [
        'acc',
        'fpga_5gnr_fec',
        'fpga_lte_fec',
        'la12xx',
        'null',
        'turbo_sw',
]

std_deps = [ 'bbdev' ]

log_prefix = 'pmd.bb'

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
