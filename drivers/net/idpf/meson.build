# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Intel Corporation

if is_windows
	build = false
	reason = 'not supported on Windows'
	subdir_done()
endif

subdir('base')
objs = [base_objs]

sources = files(
        'idpf_ethdev.c',
	'idpf_vchnl.c',
)

includes += include_directories('base')