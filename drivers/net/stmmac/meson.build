# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2026 Qualcomm Technologies, Inc.

if not is_linux
    build = false
    reason = 'only supported on linux'
    subdir_done()
endif

deps += ['bus_platform']

sources = files(
        'stmmac_ethdev.c',
        'stmmac_rxtx.c',
)
