# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

if is_ms_compiler
    subdir_done()
endif

install_data([
            'dpdk-devbind.py',
            'dpdk-pmdinfo.py',
            'dpdk-telemetry.py',
            'dpdk-hugepages.py',
            'dpdk-rss-flows.py',
            'dpdk-telemetry-exporter.py',
        ],
        install_dir: 'bin')

install_subdir(
        'telemetry-endpoints',
        install_dir: 'share/dpdk',
        strip_directory: false)
