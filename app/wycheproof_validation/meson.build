# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026

# meson file, for building this application as part of a main DPDK build.

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

deps += ['cryptodev']

if not dpdk_conf.has('RTE_HAS_JANSSON')
    build = false
    message('Skipping wycheproof_validation: Jansson is required')
else
    ext_deps += jansson_dep
    sources = files('main.c')
endif
