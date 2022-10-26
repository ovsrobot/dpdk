# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 Mellanox Technologies, Ltd

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources += files(
	'ark_ddm.c',
	'ark_common.c',
	'ark_mpu.c',
	'ark_pktchkr.c',
	'ark_pktdir.c',
	'ark_pktgen.c',
	'ark_rqp.c',
	'ark_udm.c'
)
