# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Microsoft Corporation

if not dpdk_conf.has('RTE_HAS_LIBPCAP')
    build = false
    reason = 'missing dependency, "libpcap"'
endif

sources = files('rte_pcapng.c')
headers = files('rte_pcapng.h')

deps += ['ethdev']

use_function_versioning = true
