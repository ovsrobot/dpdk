# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Advanced Micro Devices, Inc.

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

dep = dependency('e_smi_lib64', required: false, method: 'pkg-config')
if not dep.found()
    build = false
    reason = 'missing dependency, "e_smi_lib64"'
    subdir_done()
endif
sources = files('amd_uncore.c')
ext_deps += dep
deps += ['power']
