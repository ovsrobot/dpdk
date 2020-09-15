# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Siemens AG

# meson file, for building this example as part of a main DPDK build.
cc = meson.get_compiler('c')

jansson = dependency('libjansson', required: false)

if not jansson.found()
    jansson = cc.find_library('jansson', required: false)
endif

if not is_linux
        build = false
endif
if cc.has_header('sys/io.h')
    cflags += '-DHAS_SYS_IO'
endif

sources = files('main.c', 'stats.c', 'colors.c')
deps += ['ethdev']
if jansson.found()
    ext_deps += jansson
    cflags += '-DRTE_HAS_JANSSON'
endif
