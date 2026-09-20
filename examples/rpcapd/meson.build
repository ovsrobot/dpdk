# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

# since it relies on primary/secondary process
# this example is Linux only
if not is_linux
    build = false
    subdir_done()
endif

if not dpdk_conf.has('RTE_HAS_LIBPCAP')
    build = false
    reason = 'missing dependency, "libpcap"'
    subdir_done()
endif

sources = files('main.c')
ext_deps += pcap_dep
deps += ['ethdev', 'pdump', 'bpf']
