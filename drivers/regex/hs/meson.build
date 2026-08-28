# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Intel Corporation

if not dpdk_conf.get('RTE_ARCH_64')
    build = false
    reason = 'only supported on 64-bit platforms'
    subdir_done()
endif

hs_dep = dependency('libhs', required: false)
if not hs_dep.found()
    build = false
    reason = 'missing dependency, "libhs"'
    subdir_done()
endif

sources = files('hs_regex.c')
deps += ['bus_vdev', 'hash']
ext_deps += hs_dep
