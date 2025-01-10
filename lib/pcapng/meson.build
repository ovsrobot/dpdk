# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Microsoft Corporation

sources = files('rte_pcapng.c')
headers = files('rte_pcapng.h')

deps += ['ethdev']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
