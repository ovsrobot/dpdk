# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

# relies on primary/secondary process, so Linux only
if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

if not dpdk_conf.has('RTE_HAS_LIBPCAP')
    build = false
    reason = 'missing dependency, "libpcap"'
    subdir_done()
endif

sources = files(
        'capture.c',
        'filter.c',
        'main.c',
        'session.c',
        'sock.c',
)
ext_deps += pcap_dep
deps += ['ethdev', 'pdump', 'bpf', 'pcapng']
