# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

if (arch_subdir != 'arm') or (not dpdk_conf.get('RTE_ARCH_64'))
    build = false
    reason = 'only supported on aarch64'
    subdir_done()
endif

deps += ['power']
sources = files('hisi_uncore.c')
