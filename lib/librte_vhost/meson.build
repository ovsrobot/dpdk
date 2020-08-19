# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2018 Intel Corporation

if not is_linux
	build = false
	reason = 'only supported on linux'
endif
if has_libnuma == 1
	dpdk_conf.set10('RTE_LIBRTE_VHOST_NUMA', true)
endif

if arch_subdir == 'x86'
        if not machine_args.contains('-mno-avx512f')
                if cc.has_argument('-mavx512f') and cc.has_argument('-mavx512vl') and cc.has_argument('-mavx512bw')
                        cflags += ['-DCC_AVX512_SUPPORT']
                        vhost_avx512_lib = static_library('vhost_avx512_lib',
                                              'vhost_vec_avx.c',
                                              dependencies: [static_rte_eal, static_rte_mempool,
                                                  static_rte_mbuf, static_rte_ethdev, static_rte_net],
                                              include_directories: includes,
                                              c_args: [cflags, '-mavx512f', '-mavx512bw', '-mavx512vl'])
                        objs += vhost_avx512_lib.extract_objects('vhost_vec_avx.c')
                endif
        endif
endif

if (toolchain == 'gcc' and cc.version().version_compare('>=8.3.0'))
	cflags += '-DVHOST_GCC_UNROLL_PRAGMA'
elif (toolchain == 'clang' and cc.version().version_compare('>=3.7.0'))
	cflags += '-DVHOST_CLANG_UNROLL_PRAGMA'
elif (toolchain == 'icc' and cc.version().version_compare('>=16.0.0'))
	cflags += '-DVHOST_ICC_UNROLL_PRAGMA'
endif
dpdk_conf.set('RTE_LIBRTE_VHOST_POSTCOPY',
	      cc.has_header('linux/userfaultfd.h'))
cflags += '-fno-strict-aliasing'
sources = files('fd_man.c', 'iotlb.c', 'socket.c', 'vdpa.c',
		'vhost.c', 'vhost_user.c',
		'virtio_net.c', 'vhost_crypto.c')
headers = files('rte_vhost.h', 'rte_vdpa.h', 'rte_vdpa_dev.h',
		'rte_vhost_crypto.h', 'rte_vhost_async.h')
deps += ['ethdev', 'cryptodev', 'hash', 'pci']
