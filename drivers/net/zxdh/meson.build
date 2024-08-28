# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 ZTE Corporation

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

sources = files(
	'zxdh_ethdev.c',
	'zxdh_msg.c',
	'zxdh_npsdk.c',
	)
