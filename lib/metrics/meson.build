# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

sources = files('rte_metrics.c', 'rte_metrics_telemetry.c')
headers = files('rte_metrics.h', 'rte_metrics_telemetry.h')

if dpdk_conf.has('RTE_HAS_JANSSON')
    ext_deps += jansson_dep
endif

deps += ['ethdev', 'telemetry']

extra_flags = ['-Wno-vla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
