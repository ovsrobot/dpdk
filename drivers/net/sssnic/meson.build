# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

if (arch_subdir != 'x86' and arch_subdir != 'arm') or (not dpdk_conf.get('RTE_ARCH_64'))
    build = false
    reason = 'only supported on x86_64 and aarch64'
    subdir_done()
endif

subdir('base')
objs = [base_objs]

sources = files(
        'sssnic_ethdev.c',
        'sssnic_ethdev_link.c',
        'sssnic_ethdev_rx.c',
        'sssnic_ethdev_tx.c',
        'sssnic_ethdev_stats.c',
)
