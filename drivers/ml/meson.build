# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 Marvell.

drivers = [
        'cnxk',
]

std_deps = ['mldev']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
