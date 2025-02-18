# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

deps += ['common_nitrox', 'cryptodev']

sources += files(
        'nitrox_sym.c',
        'nitrox_sym_capabilities.c',
        'nitrox_sym_reqmgr.c',
)

includes += include_directories('../../common/nitrox')
