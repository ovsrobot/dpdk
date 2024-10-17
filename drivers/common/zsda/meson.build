# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 ZTE Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

deps += ['bus_pci']
sources += files(
		'zsda_common.c',
		'zsda_logs.c',
		'zsda_device.c',
		'zsda_qp.c',
		)
