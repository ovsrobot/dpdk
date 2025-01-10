# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

deps += 'log'
sources = files('telemetry.c', 'telemetry_data.c', 'telemetry_legacy.c')
headers = files('rte_telemetry.h')
includes += include_directories('../metrics')

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
