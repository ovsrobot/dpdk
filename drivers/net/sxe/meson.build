# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C), 2022, Linkdata Technology Co., Ltd.
if not is_linux or not (dpdk_conf.has('RTE_ARCH_X86_64') or dpdk_conf.has('RTE_ARCH_ARM64'))
    build = false
    reason = 'only supported on x86_64 or arm64 Linux'
    subdir_done()
+endif
cflags += ['-DSXE_DPDK']
cflags += ['-DSXE_HOST_DRIVER']

#subdir('base')
#objs = [base_objs]

deps += ['hash']
sources = files(
        'pf/sxe_main.c',
        'pf/sxe_irq.c',
        'pf/sxe_ethdev.c',
        'pf/sxe_pmd_hdc.c',
        'base/sxe_common.c',
        'base/sxe_hw.c',
)

includes += include_directories('base')
includes += include_directories('pf')
includes += include_directories('include/sxe/')
includes += include_directories('include/')
