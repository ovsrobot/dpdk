# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
# Copyright(c) 2019 Intel Corporation

sources = files('rte_rib.c', 'rte_rib6.c')
headers = files('rte_rib.h', 'rte_rib6.h')
deps += ['net', 'mempool']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
