# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

headers = files('rte_ptr_compress.h')

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
