# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2025 NebulaMatrix Technology Co., Ltd.

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

includes += include_directories('nbl_include')
includes += include_directories('nbl_hw')

sources = files(
        'nbl_ethdev.c',
        'nbl_core.c',
        'nbl_hw/nbl_hw_leonis/nbl_phy_leonis_snic.c',
)
