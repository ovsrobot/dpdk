# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Napatech A/S

if not is_linux or not dpdk_conf.has('RTE_ARCH_X86_64') or not dpdk_conf.has('RTE_ARCH_64')
    build = false
    reason = 'only supported on x86_64 and aarch64 linux'
    subdir_done()
endif

# includes
includes = [
    include_directories('.'),
    include_directories('adapter'),
    include_directories('include'),
    include_directories('nim'),
    include_directories('ntlog/include'),
    include_directories('ntutil/include'),
    include_directories('nthw'),
    include_directories('nthw/core'),
    include_directories('nthw/supported'),
    include_directories('sensors'),
    include_directories('sensors/avr_sensors'),
    include_directories('sensors/board_sensors'),
    include_directories('sensors/nim_sensors'),
    include_directories('sensors/ntavr'),
]

# all sources
sources = files(
    'adapter/nt4ga_adapter.c',
    'adapter/nt4ga_link.c',
    'adapter/nt4ga_link_100g.c',
    'adapter/nt4ga_pci_ta_tg.c',
    'adapter/nt4ga_stat.c',
    'nim/i2c_nim.c',
    'nim/nt_link_speed.c',
    'nim/qsfp_sensors.c',
    'nim/sfp_sensors.c',
    'nthw/core/nthw_clock_profiles.c',
    'nthw/core/nthw_fpga.c',
    'nthw/core/nthw_fpga_nt200a0x.c',
    'nthw/core/nthw_fpga_rst.c',
    'nthw/core/nthw_fpga_rst9563.c',
    'nthw/core/nthw_fpga_rst_nt200a0x.c',
    'nthw/core/nthw_gmf.c',
    'nthw/core/nthw_gpio_phy.c',
    'nthw/core/nthw_hif.c',
    'nthw/core/nthw_iic.c',
    'nthw/core/nthw_mac_pcs.c',
    'nthw/core/nthw_mac_pcs_xxv.c',
    'nthw/core/nthw_pci_rd_tg.c',
    'nthw/core/nthw_pci_ta.c',
    'nthw/core/nthw_pci_wr_tg.c',
    'nthw/core/nthw_pcie3.c',
    'nthw/core/nthw_rmc.c',
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
    'sensors/avr_sensors/avr_sensors.c',
    'sensors/board_sensors/board_sensors.c',
    'sensors/board_sensors/tempmon.c',
    'sensors/nim_sensors/nim_sensors.c',
    'sensors/ntavr/ntavr.c',
    'sensors/sensors.c',
)

if is_variable('default_cflags')
      cflags += default_cflags
else
      cflags += machine_args
      cflags += ['-DALLOW_INTERNAL_API']
endif

# END
