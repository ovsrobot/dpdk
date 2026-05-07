# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

if not has_flex_bison
    build = false
    reason = 'missing dependency, "flex" and/or "bison"'
    subdir_done()
endif

sources += files(
        'flow_compile_setters.c',
        'flow_compile_tables.c',
        'rte_flow_compile_api.c',
)
sources += flex_gen.process('flow_compile.l')
sources += bison_gen.process('flow_compile.y')

headers += files(
        'rte_flow_compile.h',
)

deps += ['ethdev', 'net']
