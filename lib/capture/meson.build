# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files('capture.c')

deps += ['ethdev', 'pcapng', 'bpf']

if dpdk_conf.has('RTE_HAS_LIBPCAP')
    sources += files('filter.c')
    ext_deps += pcap_dep
else
    warning('libpcap is missing, capture filtering will be disabled')
endif
