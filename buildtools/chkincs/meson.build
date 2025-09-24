# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Intel Corporation

if not get_option('check_includes')
    build = false
    subdir_done()
endif

gen_c_file_for_header = find_program('gen_c_file_for_header.py')
gen_c_files = generator(gen_c_file_for_header,
        output: '@BASENAME@.c',
        arguments: ['@INPUT@', '@OUTPUT@'])

cflags = machine_args
cflags += '-Wno-missing-field-initializers'
cflags += no_wvla_cflag
cflags += '-I../config'
cflags += '-I.'
cflags += '-Istaging'

sources = files('main.c')
sources += gen_c_files.process(dpdk_chkinc_headers)

cflags_drivers = '-Istaging/drivers'
sources_drivers = files('main.c')
sources_drivers += gen_c_files.process(dpdk_chkinc_driver_headers)

executable('chkincs', sources,
        c_args: cflags,
        install: false)

executable('chkincs-exp', sources,
        c_args: [cflags, '-DALLOW_EXPERIMENTAL_API'],
        install: false)

executable('chkincs-all', sources,
        c_args: [cflags, '-DALLOW_EXPERIMENTAL_API', '-DALLOW_INTERNAL_API'],
        install: false)

executable('chkincs-drv', sources_drivers,
        c_args: [cflags, cflags_drivers],
        install: false)

executable('chkincs-drv-exp', sources_drivers,
        c_args: [cflags, cflags_drivers, '-DALLOW_EXPERIMENTAL_API'],
        install: false)

executable('chkincs-drv-all', sources_drivers,
        c_args: [cflags, cflags_drivers, '-DALLOW_EXPERIMENTAL_API', '-DALLOW_INTERNAL_API'],
        install: false)

# run tests for c++ builds also
if not add_languages('cpp', required: false)
    subdir_done()
endif

gen_cpp_files = generator(gen_c_file_for_header,
        output: '@BASENAME@.cpp',
        arguments: ['@INPUT@', '@OUTPUT@'])

cpp_sources = files('main.cpp')
cpp_sources += gen_cpp_files.process(dpdk_chkinc_headers)

executable('chkincs-cpp', cpp_sources,
        cpp_args: ['-include', 'rte_config.h', cflags],
        install: false)

executable('chkincs-cpp-exp', cpp_sources,
        cpp_args: ['-include', 'rte_config.h', cflags, '-DALLOW_EXPERIMENTAL_API'],
        install: false)

executable('chkincs-cpp-all', cpp_sources,
        cpp_args: ['-include', 'rte_config.h', cflags, '-DALLOW_EXPERIMENTAL_API',
                   '-DALLOW_INTERNAL_API'],
        install: false)
