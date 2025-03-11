# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Stephen Hemminger

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

dep = dependency('liburing', required:false)
reason = 'missing dependency, "liburing"'
build = dep.found()
ext_deps += dep

sources = files('rte_eth_ioring.c')
require_iova_in_mbuf = false
