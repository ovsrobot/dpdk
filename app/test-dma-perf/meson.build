# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2022 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

allow_experimental_apis = true

deps += ['dmadev', 'mbuf', 'cfgfile']

sources = files(
        'main.c',
        'benchmark.c',
)
