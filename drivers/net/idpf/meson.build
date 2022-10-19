# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

includes += include_directories('../../common/idpf')
deps += ['common_idpf', 'security', 'cryptodev']

sources = files(
    'idpf_ethdev.c',
    'idpf_vchnl.c',
)
