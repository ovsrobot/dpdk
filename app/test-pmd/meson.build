# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# override default name to drop the hyphen
name = 'testpmd'
cflags += '-Wno-deprecated-declarations'
sources = files(
        '5tswap.c',
        'cmdline.c',
        'cmdline_cman.c',
        'cmdline_flow.c',
        'cmdline_mtr.c',
        'cmdline_tm.c',
        'cmd_flex_item.c',
        'config.c',
        'csumonly.c',
        'flowgen.c',
        'hairpin.c',
        'icmpecho.c',
        'ieee1588fwd.c',
        'iofwd.c',
        'macfwd.c',
        'macswap.c',
        'noisy_vnf.c',
        'parameters.c',
        'recycle_mbufs.c',
        'rxonly.c',
        'shared_rxq_fwd.c',
        'testpmd.c',
        'txonly.c',
        'util.c',
)

if dpdk_conf.has('RTE_HAS_JANSSON')
    ext_deps += jansson_dep
endif

deps += ['ethdev', 'cmdline']
if dpdk_conf.has('RTE_CRYPTO_SCHEDULER')
    optional_deps += 'crypto_scheduler'
endif
if dpdk_conf.has('RTE_LIB_BITRATESTATS')
    optional_deps += 'bitratestats'
endif
if dpdk_conf.has('RTE_LIB_BPF')
    sources += files('bpf_cmd.c')
    optional_deps += 'bpf'
endif
if dpdk_conf.has('RTE_LIB_GRO')
    optional_deps += 'gro'
endif
if dpdk_conf.has('RTE_LIB_GSO')
    optional_deps += 'gso'
endif
if dpdk_conf.has('RTE_LIB_LATENCYSTATS')
    optional_deps += 'latencystats'
endif
if dpdk_conf.has('RTE_LIB_METRICS')
    optional_deps += 'metrics'
endif
if dpdk_conf.has('RTE_LIB_PDUMP')
    optional_deps += 'pdump'
endif
if dpdk_conf.has('RTE_NET_BNXT')
    optional_deps += 'net_bnxt'
endif
if dpdk_conf.has('RTE_NET_I40E')
    optional_deps += 'net_i40e'
endif
if dpdk_conf.has('RTE_NET_IXGBE')
    optional_deps += 'net_ixgbe'
endif
if dpdk_conf.has('RTE_NET_DPAA')
    optional_deps += ['bus_dpaa', 'mempool_dpaa', 'net_dpaa']
endif

# Driver-specific commands are located in driver directories.
includes = include_directories('.')
sources += testpmd_drivers_sources
optional_deps += testpmd_drivers_deps
