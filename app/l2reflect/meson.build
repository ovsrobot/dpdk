# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Siemens AG

cc = meson.get_compiler('c')

jansson = dependency('libjansson', required: false)

if not jansson.found()
    jansson = cc.find_library('jansson', required: false)
endif

if cc.has_header('sys/io.h')
    cflags += '-DHAS_SYS_IO'
endif

sources = files('main.c', 'utils.c', 'stats.c', 'colors.c')
deps += ['ethdev']
if jansson.found()
    ext_deps += jansson
    cflags += '-DRTE_HAS_JANSSON'
endif
