# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021 Ramaxel Memory Technology, Ltd

if not (is_linux)
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

subdir('base')
objs = [base_objs]

sources = files(
	'spnic_ethdev.c',
	'spnic_io.c',
)

includes += include_directories('base')
