# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2015-2020

if is_windows
	build = false
	reason = 'not supported on Windows'
	subdir_done()
endif

subdir('base')
objs = [base_objs]

sources = files(
	'txgbe_ethdev.c',
	'txgbe_ptypes.c',
	'txgbe_pf.c',
	'txgbe_rxtx.c',
)

deps += ['hash']

includes += include_directories('base')

install_headers('rte_pmd_txgbe.h')
