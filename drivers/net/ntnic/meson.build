# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Napatech A/S

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
