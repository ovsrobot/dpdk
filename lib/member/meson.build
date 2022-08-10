# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files('rte_member.c', 'rte_member_ht.c', 'rte_member_vbf.c', 'rte_member_sketch.c')
headers = files('rte_member.h')
deps += ['hash']
includes += include_directories('../hash', '../ring')

# compile AVX512 version if:
# we are building 64-bit binary AND binutils can generate proper code
if dpdk_conf.has('RTE_ARCH_X86_64') and binutils_ok
    # compile AVX512 version if either:
    # a. we have AVX512 supported in minimum instruction set
    #    baseline
    # b. it's not minimum instruction set, but supported by
    #    compiler
    #
    # in former case, just add avx512 C file to files list
    # in latter case, compile c file to static lib, using correct
    # compiler flags, and then have the .o file from static lib
    # linked into main lib.
    sketch_avx512_cpu_support = (
        cc.get_define('__AVX512F__', args: machine_args) != ''
    )

    if sketch_avx512_cpu_support == true
	cflags += ['-DCC_AVX512_SUPPORT']
	if cc.has_argument('-mavx512f')
	    cflags += ['-mavx', '-mavx2', '-mavx512f', '-mavx512ifma', '-march=icelake-server']
	endif
	sources += files('rte_member_sketch_avx512.c')
    elif cc.has_argument('-mavx512f')
	cflags += '-DCC_AVX512_SUPPORT'
	sketch_avx512_tmp = static_library('sketch_avx512_tmp',
	    'rte_member_sketch_avx512.c',
	    include_directories: includes,
	    dependencies: static_rte_eal,
	    c_args: cflags + ['-mavx', '-mavx2', '-mavx512f', '-mavx512ifma', '-march=icelake-server'])
	objs += sketch_avx512_tmp.extract_objects('rte_member_sketch_avx512.c')
    endif
endif
