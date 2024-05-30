# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Napatech A/S

allow_experimental_apis = true

# config object
ntoss_conf = configuration_data()

# transfer options into config object
ntoss_conf.set('NT_VF_VDPA', false)

# cflags
cflags += [
    '-std=c11',
    '-DNTHW_DPDK',
]

# check option 'debug' (boolean flag derived from meson buildtype)
if get_option('debug')
    cflags += '-DDEBUG'
endif

# check if VF and vDPA support should be compiled in
if ntoss_conf.get('NT_VF_VDPA') == true
  cflags += '-DNT_VF_VDPA'
  # check if the relay core feature should be compiled in
endif

# includes
includes = [
    include_directories('..'),
    include_directories('.'),
    include_directories('include'),
    include_directories('ntlog/include'),
    include_directories('ntutil/include'),
    include_directories('nthw'),
    include_directories('nthw/supported'),
    include_directories('nthw/model'),
    # include_directories('sensors'),
    # include_directories('sensors/avr_sensors'),
    # include_directories('sensors/board_sensors'),
    # include_directories('nim/nim_sensors'),
    # include_directories('nim/include'),
    # include_directories('nim/sfp_sensors'),
    # include_directories('nim/qsfp_sensors'),
    # include_directories('sensors/ntavr'),
    # include_directories('ntconnect_modules'),
]

# ntnic_core
includes += include_directories('nthw/core/include')
includes += include_directories('nthw/core')
if fs.is_dir('nthw/core/nt200a0x')
    includes += include_directories('nthw/core/nt200a0x')
    includes += include_directories('nthw/core/nt200a0x/reset')
    includes += include_directories('nthw/core/nt200a0x/clock_profiles')
endif
if fs.is_dir('nthw/core/nt50b01')
    includes += include_directories('nthw/core/nt50b01')
    includes += include_directories('nthw/core/nt50b01/reset')
    includes += include_directories('nthw/core/nt50b01/clock_profiles')
endif
if fs.is_dir('nthw/core/nt400dxx')
    includes += include_directories('nthw/core/nt400dxx')
    includes += include_directories('nthw/core/nt400dxx/reset')
endif
# includes += include_directories('adapter')
# includes += include_directories('link_mgmt')
# includes += include_directories('nim')
# includes += include_directories('nim/nim_sensors')
if fs.is_dir('nim/sfp_sensors')
    includes += include_directories('nim/sfp_sensors')
endif
if fs.is_dir('nim/qsfp_sensors')
    includes += include_directories('nim/qsfp_sensors')
endif

# deps
deps += 'vhost'

# headers
headers = files('rte_pmd_ntnic.h')

# all sources
sources = files(
    'dpdk_mod_reg.c',
    'nthw/supported/nthw_fpga_9563_055_039_0000.c',
    'nthw/supported/nthw_fpga_instances.c',
    'nthw/supported/nthw_fpga_mod_str_map.c',
    'nthw/model/nthw_fpga_model.c',
    'nthw/nthw_epp.c',
    'nthw/nthw_platform.c',
    'nthw/nthw_rac.c',
    'nthw/nthw_utils.c',
    'ntlog/ntlog.c',
    'ntnic_ethdev.c',
    'ntnic_mod_reg.c',
    'ntnic_vfio.c',
    'ntutil/nt_util.c',
)
# END
