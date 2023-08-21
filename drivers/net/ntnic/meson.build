# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Napatech A/S

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

if not dpdk_conf.has('RTE_ARCH_X86_64')
    build = false
    reason = 'only supported on x86_64'
    subdir_done()
endif

# includes
includes = [
    include_directories('.'),
    include_directories('include'),
    include_directories('nthw'),
    include_directories('nthw/supported'),
]

# all sources
sources = files(
    'nthw/supported/nthw_fpga_9563_055_024_0000.c',
)

if is_variable('default_cflags')
      cflags += default_cflags
else
      cflags += machine_args
      cflags += ['-DALLOW_INTERNAL_API']
endif

# END
