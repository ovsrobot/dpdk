# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

subdir('base')

sources = files(
        'qede_debug.c',
        'qede_ethdev.c',
        'qede_filter.c',
        'qede_main.c',
        'qede_regs.c',
        'qede_rxtx.c',
        'qede_sriov.c',
)

if cc.has_argument('-Wno-format-nonliteral')
    cflags += '-Wno-format-nonliteral'
endif
# no packet Rx with gcc > 11 with compiling with default -O3 or -O2
if (cc.get_id() == 'gcc' and cc.version().version_compare('>=12.0'))
    cflags += '-O1'
endif
