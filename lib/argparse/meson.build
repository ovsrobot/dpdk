# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 HiSilicon Limited.

sources = files('rte_argparse.c')
headers = files('rte_argparse.h')

deps += ['log']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
