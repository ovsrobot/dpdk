# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2019 Intel Corporation

includes += global_inc
subdir('include')

subdir('common')

if not is_windows
    subdir('unix')
endif

subdir(exec_env)

arch_headers = []
arch_indirect_headers = []
subdir(arch_subdir)
staged_headers_deps += declare_dependency(sources:
        custom_target('eal_arch_header_staging',
                output: 'eal_arch_header_staging.stamp',
                command: [stage_headers_cmd, staging_dir, '@OUTPUT@',
                    arch_headers + arch_indirect_headers],
                install: false,
        )
)

deps += ['log', 'kvargs']
if not is_windows
    deps += ['telemetry']
endif
if dpdk_conf.has('RTE_USE_LIBBSD')
    ext_deps += libbsd
endif
if dpdk_conf.has('RTE_HAS_LIBARCHIVE')
    ext_deps += libarchive
endif
if cc.has_function('getentropy', prefix : '#include <unistd.h>')
    cflags += '-DRTE_LIBEAL_USE_GETENTROPY'
endif

if is_freebsd
    annotate_locks = false
endif
