# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA Corporation & Affiliates

headers = files(
        'rte_gpudev.h',
)

driver_sdk_headers = files(
        'gpudev_driver.h',
)

sources = files(
        'gpudev.c',
)

deps += ['mbuf']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
