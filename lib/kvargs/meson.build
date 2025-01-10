# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

deps += 'log'
sources = files('rte_kvargs.c')
headers = files('rte_kvargs.h')

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
