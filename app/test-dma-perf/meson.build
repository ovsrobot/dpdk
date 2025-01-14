# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2023 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

deps += ['dmadev', 'mbuf', 'cfgfile']

sources = files(
        'main.c',
        'benchmark.c',
)

extra_flags = ['-Wno-vla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
