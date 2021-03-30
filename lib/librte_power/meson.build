# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

if not is_linux
	build = false
	reason = 'only supported on Linux'
endif

# we do some snprintf magic so silence format-nonliteral
flag_nonliteral = '-Wno-format-nonliteral'
if cc.has_argument(flag_nonliteral)
	cflags += flag_nonliteral
endif

sources = files('rte_power.c', 'power_acpi_cpufreq.c',
		'power_kvm_vm.c', 'guest_channel.c',
		'rte_power_empty_poll.c',
		'power_pstate_cpufreq.c',
		'rte_power_pmd_mgmt.c',
		'power_common.c')
headers = files('rte_power.h','rte_power_empty_poll.h',
	'rte_power_pmd_mgmt.h',
	'rte_power_guest_channel.h')
deps += ['timer', 'ethdev']
