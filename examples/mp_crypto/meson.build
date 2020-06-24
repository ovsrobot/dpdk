# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

if not dpdk_conf.has('RTE_LIBRTE_CRYPTODEV')
        build = false
        subdir_done()
endif

allow_experimental_apis = true
deps += ['cryptodev']
sources = files(
	'main.c', 'mp_crypto.c', 'mp_crypto_parser.c', 'mp_crypto_vectors.c', 'mp_crypto_ipc.c'
)
