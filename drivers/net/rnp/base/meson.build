# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Mucse IC Design Ltd.

sources = [
        'rnp_mbx.c',
        'rnp_fw_cmd.c',
        'rnp_mbx_fw.c',
        'rnp_common.c',
        'rnp_mac.c',
]

error_cflags = ['-Wno-unused-value',
        '-Wno-unused-but-set-variable',
        '-Wno-unused-parameter',
        ]
c_args = cflags
foreach flag: error_cflags
    if cc.has_argument(flag)
        c_args += flag
    endif
endforeach

base_lib = static_library('rnp_base', sources,
    dependencies: [static_rte_eal, static_rte_net, static_rte_ethdev],
    c_args: c_args)
base_objs = base_lib.extract_all_objects(recursive: true)
