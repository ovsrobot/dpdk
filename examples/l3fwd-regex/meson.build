# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2020 Marvell International Ltd.

# meson file, for building this example as part of a main DPDK build.

allow_experimental_apis = true
deps += ['lpm', 'regexdev']
sources = files(
	'l3fwd_lpm.c', 'l3fwd_regex.c', 'main.c'
)
