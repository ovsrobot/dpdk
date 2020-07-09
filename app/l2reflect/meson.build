# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Siemens AG

# meson file, for building this example as part of a main DPDK build.

cjson = dependency('libcjson', required: false)

if not cjson.found()
    cc = meson.get_compiler('c')
    cjson = cc.find_library('cjson', required: false)
endif

if not is_linux
        build = false
endif

sources = files('main.c', 'stats.c')
deps += ['ethdev']
if cjson.found()
    ext_deps += cjson
    cflags += '-DRTE_HAS_CJSON'
endif
