# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

if host_machine.system() == 'windows'
	build = false
	reason = 'not supported on Windows'
	subdir_done()
endif

sources = files('vdev.c',
	'vdev_params.c')
install_headers('rte_bus_vdev.h')

deps += ['kvargs']
