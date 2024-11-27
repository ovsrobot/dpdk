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
if dpdk_conf.has('RTE_LIB_BPF')
    sources += files('bpf_cmd.c')
endif

deps += ['ethdev', 'cmdline']
optional_deps += [
    'crypto_scheduler',
    'bitratestats',
    'bpf',
    'gro',
    'gso',
    'latencystats',
    'metrics',
    'pdump',
    'net_bnxt',
    'net_i40e',
    'net_ixgbe',
    'bus_dpaa',
    'mempool_dpaa',
    'net_dpaa'
]

# Driver-specific commands are located in driver directories.
includes = include_directories('.')
sources += testpmd_drivers_sources
optional_deps += testpmd_drivers_deps
