# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Mucse IC Design Ltd.
#
if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files(
		'rnp_ethdev.c',
		'rnp_mbx.c',
		'rnp_mbx_fw.c',
		'rnp_rxtx.c',
		'base/rnp_api.c',
)

includes += include_directories('base')
