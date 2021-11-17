# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA Corporation & Affiliates

if dpdk_conf.has('RTE_LIB_GPUDEV')
    sources = files('main.c')
    deps = ['gpudev', 'ethdev']
else
    build = false
    reason = 'gpudev library is disabled'
    subdir_done()
endif

