# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

if is_ms_compiler
    build = false
    reason = 'not supported building with Visual Studio Toolset'
    subdir_done()
endif

extra_flags = []

foreach flag: extra_flags
    if cc.has_argument(flag)
        cflags += flag
    endif
endforeach

sources = files(
        'rte_mempool.c',
        'rte_mempool_ops.c',
        'rte_mempool_ops_default.c',
        'mempool_trace_points.c',
)
headers = files(
        'rte_mempool.h',
        'rte_mempool_trace_fp.h',
)
deps += ['ring', 'telemetry']
