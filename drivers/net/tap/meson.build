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
        'tap_bpf_api.c',
        'tap_flow.c',
        'tap_intr.c',
        'tap_netlink.c',
        'tap_tcmsgs.c',
)

deps = ['bus_vdev', 'gso', 'hash']

cflags += '-DTAP_MAX_QUEUES=8'

# input array for meson symbol search:
# [ "MACRO to define if found", "header for the search",
#   "enum/define", "symbol to search" ]
#
args = [
        [ 'HAVE_TC_ACT_BPF', 'linux/tc_act/tc_bpf.h', 'TCA_ACT_BPF_UNSPEC' ],
]
config = configuration_data()
foreach arg:args
    config.set(arg[0], cc.has_header_symbol(arg[1], arg[2]))
endforeach
configure_file(output : 'tap_autoconf.h', configuration : config)

require_iova_in_mbuf = false
