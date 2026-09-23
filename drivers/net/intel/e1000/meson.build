# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

subdir('base')

sources += files(
        'e1000_logs.c',
        'em_ethdev.c',
        'em_rxtx.c',
        'igb_ethdev.c',
        'igb_flow.c',
        'igb_pf.c',
        'igb_rxtx.c',
)

# do not build IGC on Windows
if not is_windows
        sources += files(
                'igc_ethdev.c',
                'igc_logs.c',
                'igc_filter.c',
                'igc_flow.c',
                'igc_txrx.c',
        )
endif

# testpmd crashes with gcc > 11 with compiling with default -O3 or -O2
if (cc.get_id() == 'gcc' and cc.version().version_compare('>=12.0'))
    cflags += '-O1'
endif
