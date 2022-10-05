# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif
if not dpdk_conf.has('kni')
    build = false
    reason = 'needs deprecated lib, "kni"'
    subdir_done()
endif

deps += 'kni'
sources = files('rte_eth_kni.c')
