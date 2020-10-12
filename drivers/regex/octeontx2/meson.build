# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2020 Marvell International Ltd.
#

if not is_linux
	build = false
	reason = 'only supported on Linux'
endif

path = get_option('ree_compiler_sdk')
lib_dir = path + '/lib'
inc_dir = path + '/include'

if dpdk_conf.has('RTE_LIBRTE_PMD_OCTEONTX2_REGEX_COMPILER')
	lib = cc.find_library('librxp_compiler', dirs : [lib_dir], required: false)
	if not lib.found()
		build = false
		reason = 'missing dependency, "librxp_compiler"'
	else
		ext_deps += lib
		ext_deps += cc.find_library('libstdc++', required: true)
		includes += include_directories(inc_dir)
		cflags += ['-DREE_COMPILER_SDK']
	endif
endif

sources = files('otx2_regexdev.c',
		'otx2_regexdev_hw_access.c',
		'otx2_regexdev_mbox.c',
		'otx2_regexdev_compiler.c'
		)

extra_flags = []
# This integrated controller runs only on a arm64 machine, remove 32bit warnings
if not dpdk_conf.get('RTE_ARCH_64')
	extra_flags += ['-Wno-int-to-pointer-cast', '-Wno-pointer-to-int-cast']
endif

# for clang 32-bit compiles we need libatomic for 64-bit atomic ops
if cc.get_id() == 'clang' and dpdk_conf.get('RTE_ARCH_64') == false
	ext_deps += cc.find_library('atomic')
endif

foreach flag: extra_flags
	if cc.has_argument(flag)
		cflags += flag
	endif
endforeach

name = 'octeontx2_regex'
deps += ['bus_pci', 'common_octeontx2', 'regexdev']

includes += include_directories('../../common/octeontx2')
