# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 Intel Corporation

includes += global_inc
sources = files(
        'log.c',
        'log_timestamp.c',
)

if is_windows
    sources += files('log_stubs.c')
else
    sources += files('log_syslog.c')
if is_linux
    sources += files('log_journal.c')
endif
endif

headers = files('rte_log.h')
