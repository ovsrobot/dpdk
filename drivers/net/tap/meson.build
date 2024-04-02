# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 Luca Boccassi <bluca@debian.org>

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif
sources = files(
        'rte_eth_tap.c',
        'tap_flow.c',
        'tap_intr.c',
        'tap_netlink.c',
        'tap_tcmsgs.c',
)

max_queues = '-DTAP_MAX_QUEUES=16'
cflags += max_queues

subdir('bpf')
if enable_tap_rss
    cflags += '-DHAVE_BPF_RSS'
    ext_deps += libbpf
    sources += tap_rss_skel_h
endif

deps = ['bus_vdev', 'gso', 'hash']

require_iova_in_mbuf = false
