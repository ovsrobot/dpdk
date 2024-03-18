# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 Intel Corporation

includes += global_inc
sources = files('log.c')

if is_windows
    sources += files('log_windows.c')
else
    sources += files('log_unix.c')
endif

headers = files('rte_log.h')
