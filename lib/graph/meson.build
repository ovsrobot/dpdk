# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2020 Marvell International Ltd.

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files(
        'node.c',
        'graph.c',
        'graph_ops.c',
        'graph_debug.c',
        'graph_stats.c',
        'graph_populate.c',
        'graph_pcap_trace.c',
)
headers = files('rte_graph.h', 'rte_graph_worker.h', 'rte_graph_pcap_trace.h')

deps += ['eal', 'mbuf', 'ethdev', 'pcapng']
