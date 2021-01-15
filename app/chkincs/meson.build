# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2021 Intel Corporation

if not get_option('test_includes')
	build = false
	subdir_done()
endif

if is_windows
	# for windows, the shebang line in the script won't work.
	error('option "test_includes" is not supported on windows')
endif

gen_c_file_for_header = find_program('gen_c_file_for_header.py')
gen_c_files = generator(gen_c_file_for_header,
	output: '@BASENAME@.c',
	arguments: ['@INPUT@', '@OUTPUT@'])

cflags += '-Wno-unused-function' # needed if we include generic headers

# some ethdev headers depend on bus headers
includes += include_directories('../../drivers/bus/pci',
	'../../drivers/bus/vdev')

sources += files('main.c')
sources += gen_c_files.process(dpdk_chkinc_headers)

deps = enabled_libs
