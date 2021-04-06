# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018-2020

if is_windows
	build = false
	reason = 'not supported on Windows'
	subdir_done()
endif

subdir('base')
objs = [base_objs]

sources = files(
	'ngbe_ethdev.c',
)

includes += include_directories('base')

