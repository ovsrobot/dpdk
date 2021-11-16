# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA Corporation & Affiliates

if not is_linux
        build = false
        reason = 'only supported on Linux'
endif

cuda_h_found = cc.has_header('cuda.h')
cuda_typeh_found = cc.has_header('cudaTypedefs.h')

if not cuda_h_found or not cuda_typeh_found
        build = false
        reason = 'missing dependency cuda headers cuda.h and cudaTypedefs.h'
endif

deps += ['gpudev','pci','bus_pci']
sources = files('cuda.c')
