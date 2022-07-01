# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Microsoft Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

deps += ['pci', 'bus_pci', 'net', 'eal', 'kvargs']

sources += files(
	'mana.c',
	'mp.c',
)

lib = cc.find_library('ibverbs', required:false)
if lib.found()
    ext_deps += lib
else
    build = false
    reason = 'missing dependency ibverbs'
    subdir_done()
endif


lib = cc.find_library('mana', required:false)
if lib.found()
    ext_deps += lib
else
    build = false
    reason = 'missing dependency mana'
    subdir_done()
endif
