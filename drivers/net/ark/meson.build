# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

deps += ['common_ark']

sources = files(
        'ark_ethdev.c',
        'ark_ethdev_rx.c',
        'ark_ethdev_tx.c',
        'ark_ethdev_logs.c',
)

includes += include_directories('../../common/ark')
