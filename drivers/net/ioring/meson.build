# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Stephen Hemminger

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

ext_deps += dependency('liburing', required:true)

sources = files('rte_eth_ioring.c')
require_iova_in_mbuf = false
