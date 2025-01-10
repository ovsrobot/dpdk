# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2019 Intel Corporation

sources = files('rte_security.c')
headers = files('rte_security.h', 'rte_security_driver.h')
deps += ['mempool', 'cryptodev', 'net']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
