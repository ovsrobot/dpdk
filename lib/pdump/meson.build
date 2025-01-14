# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

extra_flags = ['-Wno-vla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach

sources = files('rte_pdump.c')
headers = files('rte_pdump.h')
deps += ['ethdev', 'bpf', 'pcapng']
