# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
# Copyright(c) 2019 Intel Corporation

sources = files('rte_fib.c', 'rte_fib6.c', 'dir24_8.c', 'trie.c')
headers = files('rte_fib.h', 'rte_fib6.h')
deps += ['rib']

if arch_subdir == 'x86' and not machine_args.contains('-mno-avx512f')
	# compile AVX512 version if either:
	# a. we have AVX512F supported in minimum instruction set baseline
	# b. it's not minimum instruction set, but supported by compiler
	if dpdk_conf.has('RTE_MACHINE_CPUFLAG_AVX512F')
		cflags += ['-DCC_DIR24_8_AVX512_SUPPORT']
		sources += files('dir24_8_avx512.c')
		cflags += ['-DCC_TRIE_AVX512_SUPPORT']
		sources += files('trie_avx512.c')
	elif cc.has_multi_arguments('-mavx512f', '-mavx512dq')
		dir24_8_avx512_tmp = static_library('dir24_8_avx512_tmp',
				'dir24_8_avx512.c',
				dependencies: static_rte_eal,
				c_args: cflags + ['-mavx512f', '-mavx512dq'])
		objs += dir24_8_avx512_tmp.extract_objects('dir24_8_avx512.c')
		cflags += '-DCC_DIR24_8_AVX512_SUPPORT'
		# TRIE AVX512 implementation uses avx512bw intrinsics along with
		# avx512f and avx512dq
		if cc.has_argument('-mavx512bw')
			trie_avx512_tmp = static_library('trie_avx512_tmp',
				'trie_avx512.c',
				dependencies: static_rte_eal,
				c_args: cflags + ['-mavx512f', \
					'-mavx512dq', '-mavx512bw'])
			objs += trie_avx512_tmp.extract_objects('trie_avx512.c')
			cflags += '-DCC_TRIE_AVX512_SUPPORT'
		endif
	endif
endif

