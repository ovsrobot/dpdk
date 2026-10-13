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
            'dpdk-telemetry-watcher.py',
        ],
        install_dir: 'bin')

install_subdir(
        'telemetry-endpoints',
        install_dir: 'share/dpdk',
        strip_directory: false)

# Wireshark extcap helper does not depend on anything from DPDK
# and speaks the telemetry socket protocol directly.
if not is_windows
    extcap_cflags = []
    extcap_deps = []

    cap_dep = dependency('libcap', required: false)
    if cap_dep.found()
        extcap_cflags += '-DHAVE_LIBCAP'
        extcap_deps += cap_dep
    endif

    executable('dpdk-wireshark-extcap',
            files('dpdk-wireshark-extcap.c'),
            # only for the project-wide '-include rte_config.h'
            include_directories: config_inc,
            c_args: extcap_cflags,
            dependencies: extcap_deps,
            pie: true,
            install: true,
            install_dir: 'bin')
endif
