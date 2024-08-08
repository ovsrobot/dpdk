# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 ZTE Corporation

config_flag_fmt = 'RTE_LIBRTE_@0@_COMMON'

deps += ['bus_pci', 'compressdev']
sources += files(
		'zsda_common.c',
		'zsda_logs.c',
		'zsda_device.c',
		'zsda_qp.c',
		)

zsda_compress = true
zsda_compress_path = 'compress/zsda'
zsda_compress_relpath = '../../' + zsda_compress_path
includes += include_directories(zsda_compress_relpath)

if zsda_compress
zlib = dependency('zlib', required: false, method: 'pkg-config')
	foreach f: ['zsda_comp_pmd.c', 'zsda_comp.c']
		sources += files(join_paths(zsda_compress_relpath, f))
	endforeach
	ext_deps += zlib
endif
