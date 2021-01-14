# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

if not is_linux
	build = false
	reason = 'only supported on Linux'
endif

sources = files('vfio_user_base.c', 'vfio_user_server.c')
headers = files('rte_vfio_user.h')
