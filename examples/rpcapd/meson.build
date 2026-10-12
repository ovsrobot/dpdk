# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

# relies on primary/secondary process, so Linux only
if not is_linux
    build = false
    subdir_done()
endif

if not dpdk_conf.has('RTE_HAS_LIBPCAP')
    build = false
    subdir_done()
endif

ext_deps += pcap_dep
deps += ['pdump', 'bpf']
sources = files(
        'capture.c',
        'filter.c',
        'main.c',
        'session.c',
        'sock.c',
)
