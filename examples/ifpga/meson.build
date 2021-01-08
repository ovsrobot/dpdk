# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2021 Intel Corporation

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

# require the raw_ifpga library
build = dpdk_conf.has('RTE_RAW_IFPGA')
if not build
	subdir_done()
endif

deps += 'raw_ifpga'
allow_experimental_apis = true
sources = files(
	'main.c', 'commands.c'
)
