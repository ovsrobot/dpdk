# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019-2021 Intel Corporation

sources = files(
        'sff_common.c',
        'sff_8079.c',
        'sff_8472.c',
        'sff_8636.c',
        'sff_telemetry.c'
)

deps += ['ethdev']

if cc.has_argument('-Wno-pointer-to-int-cast')
        cflags += '-Wno-pointer-to-int-cast'
endif