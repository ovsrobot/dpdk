# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 Luca Boccassi <bluca@debian.org>

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

# The flower classifier was introduced in Linux 4.2
# any kernel older than that is outside current DPDK support
if not cc.has_header_symbol('linux/pkt_cls.h', 'TCA_FLOWER_ACT')
    build = false
    reason = 'does not support TC flower'
endif

sources = files(
        'rte_eth_tap.c',
        'tap_flow.c',
        'tap_intr.c',
        'tap_netlink.c',
        'tap_tcmsgs.c',
        )

deps = ['bus_vdev', 'gso', 'hash']

max_queues = '-DTAP_MAX_QUEUES=16'
cflags += max_queues

require_iova_in_mbuf = false

subdir('bpf')
if enable_tap_rss
    cflags += '-DHAVE_BPF_RSS'
    ext_deps += libbpf
    sources += tap_rss_skel_h
endif
