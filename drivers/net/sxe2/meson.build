# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
#执行子目录base，并获取目标对象

cflags += ['-DSXE2_DPDK_DRIVER']
cflags += ['-DFPGA_VER_ASIC']
if arch_subdir != 'arm'
        cflags += ['-Werror']
endif

cflags += ['-g']

deps += ['common_sxe2', 'hash','cryptodev','security']

if arch_subdir == 'x86'
        sources += files('sxe2_txrx_vec_sse.c')

        if is_windows and cc.get_id() != 'clang'
                cflags += ['-fno-asynchronous-unwind-tables']
        endif
endif

sources += files(
        'sxe2_ethdev.c',
        'sxe2_cmd_chnl.c',
        'sxe2_vsi.c',
        'sxe2_queue.c',
        'sxe2_tx.c',
        'sxe2_rx.c',
        'sxe2_txrx_poll.c',
        'sxe2_txrx.c',
        'sxe2_txrx_vec.c',
)

allow_internal_get_api = true
