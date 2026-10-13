# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

deps += ['cryptodev']

if not dpdk_conf.has('RTE_HAS_JANSSON')
    build = false
    message('Skipping wycheproof_validation: Jansson is required')
else
    ext_deps += jansson_dep
    sources = files('main.c')
endif
