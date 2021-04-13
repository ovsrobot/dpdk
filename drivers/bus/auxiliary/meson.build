# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2021 Mellanox Technologies, Ltd

if is_linux
	headers = files('rte_bus_auxiliary.h')
	sources = files('auxiliary_common.c',
		'auxiliary_params.c',
		'linux/auxiliary.c')
	includes += include_directories('linux')
	deps += ['kvargs']
endif
if not is_linux
	build = false
	reason = 'only supported on Linux'
	subdir_done()
endif

