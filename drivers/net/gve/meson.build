# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022-2023 Google LLC
# Copyright (c) 2022-2023 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files(
        'base/gve_adminq.c',
        'gve_rx.c',
        'gve_tx.c',
        'gve_ethdev.c',
)
includes += include_directories('base')
