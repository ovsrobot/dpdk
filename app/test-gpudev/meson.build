# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA Corporation & Affiliates

sources = files('main.c')
deps = ['gpudev', 'ethdev']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
