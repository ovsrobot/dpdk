# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018-2021 Intel Corporation

sources = [
        'ice_controlq.c',
        'ice_common.c',
        'ice_sched.c',
        'ice_switch.c',
        'ice_nvm.c',
        'ice_flex_pipe.c',
        'ice_flow.c',
        'ice_dcb.c',
        'ice_fdir.c',
        'ice_acl.c',
        'ice_acl_ctrl.c',
        'ice_vlan_mode.c',
]

error_cflags = [
        '-Wno-unused-value',
        '-Wno-unused-but-set-variable',
        '-Wno-unused-variable',
        '-Wno-unused-parameter',
]

# Bugzilla ID: 678
if (toolchain == 'gcc' and cc.version().version_compare('>=11.0.0'))
    error_cflags += ['-Wno-array-bounds']
endif

if is_windows and cc.get_id() != 'clang'
    cflags += ['-fno-asynchronous-unwind-tables']
endif

c_args = cflags

foreach flag: error_cflags
    if cc.has_argument(flag)
        c_args += flag
    endif
endforeach

base_lib = static_library('ice_base', sources,
        dependencies: static_rte_eal,
        c_args: c_args)
base_objs = base_lib.extract_all_objects()
