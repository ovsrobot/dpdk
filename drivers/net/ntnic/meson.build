# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Napatech A/S

# cflags
cflags += [
    '-std=c11',
]

# includes
includes = [
    include_directories('.'),
    include_directories('include'),
    include_directories('ntlog/include'),
    include_directories('ntutil/include'),
    include_directories('nthw'),
    include_directories('nthw/core'),
    include_directories('nthw/supported'),
]

# all sources
sources = files(
    'nthw/core/nthw_clock_profiles.c',
    'nthw/core/nthw_fpga.c',
    'nthw/core/nthw_fpga_nt200a0x.c',
    'nthw/core/nthw_fpga_rst.c',
    'nthw/core/nthw_fpga_rst9563.c',
    'nthw/core/nthw_fpga_rst_nt200a0x.c',
    'nthw/core/nthw_gpio_phy.c',
    'nthw/core/nthw_hif.c',
    'nthw/core/nthw_iic.c',
    'nthw/core/nthw_mac_pcs.c',
    'nthw/core/nthw_mac_pcs_xxv.c',
    'nthw/core/nthw_pci_rd_tg.c',
    'nthw/core/nthw_pci_ta.c',
    'nthw/core/nthw_pci_wr_tg.c',
    'nthw/core/nthw_pcie3.c',
    'nthw/core/nthw_sdc.c',
    'nthw/core/nthw_si5340.c',
    'nthw/core/nthw_spi_v3.c',
    'nthw/core/nthw_spim.c',
    'nthw/core/nthw_spis.c',
    'nthw/core/nthw_tsm.c',
    'nthw/nthw_fpga_model.c',
    'nthw/nthw_dbs.c',
    'nthw/nthw_epp.c',
    'nthw/nthw_platform.c',
    'nthw/nthw_rac.c',
    'nthw/nthw_stat.c',
    'nthw/supported/nthw_fpga_9563_055_024_0000.c',
    'ntlog/ntlog.c',
    'ntutil/nt_util.c',
)

if is_variable('default_cflags')
      cflags += default_cflags
else
      cflags += machine_args
      cflags += ['-DALLOW_INTERNAL_API']
endif

# END
