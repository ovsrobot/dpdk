# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA Corporation & Affiliates

if not is_linux
        build = false
        reason = 'only supported on Linux'
endif

deps += ['gpudev','pci','bus_pci']
sources = files('cuda.c')
