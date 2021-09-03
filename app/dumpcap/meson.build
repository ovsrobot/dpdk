# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Microsoft Corporation

if is_windows
	build = false
	reason = 'not supported on Windows'
	subdir_done()
endif

sources = files('main.c')
deps += ['ethdev', 'pdump', 'pcapng']
