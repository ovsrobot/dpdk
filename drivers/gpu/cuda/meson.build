# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA Corporation & Affiliates

if not is_linux
        build = false
        reason = 'only supported on Linux'
endif

cuda_dep = dependency('cuda', version : '>=11', modules: ['cuda'])
ext_deps += cuda_dep

deps += ['gpudev','pci','bus_pci', 'hash']
sources = files('cuda.c')
