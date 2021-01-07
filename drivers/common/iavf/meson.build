# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2020 Intel Corporation

includes += include_directories('vfio_user')

sources = files(
	'iavf_adminq.c',
	'iavf_common.c',
	'iavf_impl.c',
	'vfio_user/vfio_user_pci.c'
)

deps += ['vfio_user']

if cc.has_argument('-Wno-pointer-to-int-cast')
        cflags += '-Wno-pointer-to-int-cast'
endif
