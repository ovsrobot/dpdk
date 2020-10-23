# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation.
# Copyright(c) 2017 Cavium, Inc
# Copyright(c) 2020 PANTHEON.tech s.r.o.

# set arm_force_native_march if you want to use machine args below
# instead of discovered values; only works when doing an actual native build
arm_force_native_march = false
native_machine_args = ['-march=native', '-mtune=native']

# common flags to all aarch64 builds, with lowest priority
flags_common_default = [
	# Accelarate rte_memcpy. Be sure to run unit test (memcpy_perf_autotest)
	# to determine the best threshold in code. Refer to notes in source file
	# (lib/librte_eal/arm/include/rte_memcpy_64.h) for more info.
	['RTE_ARCH_ARM64_MEMCPY', false],
	#	['RTE_ARM64_MEMCPY_ALIGNED_THRESHOLD', 2048],
	#	['RTE_ARM64_MEMCPY_UNALIGNED_THRESHOLD', 512],

	# Leave below RTE_ARM64_MEMCPY_xxx options commented out,
	# unless there are strong reasons.
	#	['RTE_ARM64_MEMCPY_SKIP_GCC_VER_CHECK', false],
	#	['RTE_ARM64_MEMCPY_ALIGN_MASK', 0xF],
	#	['RTE_ARM64_MEMCPY_STRICT_ALIGN', false],

	['RTE_NET_FM10K', false],
	['RTE_NET_SFC_EFX', false],
	['RTE_NET_AVP', false],

	['RTE_SCHED_VECTOR', false],
	['RTE_ARM_USE_WFE', false],
	['RTE_CACHE_LINE_SIZE', 128],
	['RTE_ARCH_ARM64', true]
]

# implementer specific aarch64 flags, with middle priority
# (will overwrite common flags)
flags_generic = [
	['RTE_MACHINE', '"armv8a"'],
	['RTE_MAX_LCORE', 256],
	['RTE_MAX_NUMA_NODES', 4],
	['RTE_USE_C11_MEM_MODEL', true],
	['RTE_CACHE_LINE_SIZE', 128]
]
flags_arm = [
	['RTE_MACHINE', '"armv8a"'],
	['RTE_MAX_LCORE', 16],
	['RTE_MAX_NUMA_NODES', 1],
	['RTE_USE_C11_MEM_MODEL', true],
	['RTE_CACHE_LINE_SIZE', 64]
]
flags_cavium = [
	['RTE_CACHE_LINE_SIZE', 128],
	['RTE_MAX_NUMA_NODES', 2],
	['RTE_MAX_LCORE', 96],
	['RTE_MAX_VFIO_GROUPS', 128]
]
flags_dpaa = [
	['RTE_MACHINE', '"dpaa"'],
	['RTE_USE_C11_MEM_MODEL', true],
	['RTE_CACHE_LINE_SIZE', 64],
	['RTE_MAX_NUMA_NODES', 1],
	['RTE_MAX_LCORE', 16],
	['RTE_LIBRTE_DPAA2_USE_PHYS_IOVA', false]
]
flags_emag = [
	['RTE_MACHINE', '"emag"'],
	['RTE_MAX_NUMA_NODES', 1],
	['RTE_MAX_LCORE', 32],
	['RTE_CACHE_LINE_SIZE', 64]
]
flags_armada = [
	['RTE_MACHINE', '"armv8a"'],
	['RTE_MAX_NUMA_NODES', 1],
	['RTE_MAX_LCORE', 16],
	['RTE_CACHE_LINE_SIZE', 64]
]

# part number specific aarch64 flags, with highest priority
# (will overwrite both common and implementer specific flags)
flags_n1sdp_extra = [
	['RTE_MACHINE', '"n1sdp"'],
	['RTE_MAX_NUMA_NODES', 1],
	['RTE_MAX_LCORE', 4],
	['RTE_EAL_NUMA_AWARE_HUGEPAGES', false],
	['RTE_LIBRTE_VHOST_NUMA', false]
]
flags_thunderx_extra = [
	['RTE_MACHINE', '"thunderx"'],
	['RTE_USE_C11_MEM_MODEL', false]
]
flags_thunderx2_extra = [
	['RTE_MACHINE', '"thunderx2"'],
	['RTE_CACHE_LINE_SIZE', 64],
	['RTE_MAX_NUMA_NODES', 2],
	['RTE_MAX_LCORE', 256],
	['RTE_ARM_FEATURE_ATOMICS', true],
	['RTE_USE_C11_MEM_MODEL', true]
]
flags_octeontx2_extra = [
	['RTE_MACHINE', '"octeontx2"'],
	['RTE_MAX_NUMA_NODES', 1],
	['RTE_MAX_LCORE', 36],
	['RTE_ARM_FEATURE_ATOMICS', true],
	['RTE_EAL_IGB_UIO', false],
	['RTE_USE_C11_MEM_MODEL', true]
]
# arm config (implementer 0x41) is the default config
pn_config_default = {
	'generic': [['-march=armv8-a+crc', '-moutline-atomics']],
	'0xd03': [['-mcpu=cortex-a53']],
	'0xd04': [['-mcpu=cortex-a35']],
	'0xd07': [['-mcpu=cortex-a57']],
	'0xd08': [['-mcpu=cortex-a72']],
	'0xd09': [['-mcpu=cortex-a73']],
	'0xd0a': [['-mcpu=cortex-a75']],
	'0xd0b': [['-mcpu=cortex-a76']],
	'0xd0c': [['-march=armv8.2-a+crc+crypto', '-mcpu=neoverse-n1'], flags_n1sdp_extra]
}
pn_config_cavium = {
	'generic': [['-march=armv8-a+crc+crypto', '-mcpu=thunderx']],
	'0xa1': [['-mcpu=thunderxt88'], flags_thunderx_extra],
	'0xa2': [['-mcpu=thunderxt81'], flags_thunderx_extra],
	'0xa3': [['-mcpu=thunderxt83'], flags_thunderx_extra],
	'0xaf': [['-march=armv8.1-a+crc+crypto','-mcpu=thunderx2t99'], flags_thunderx2_extra],
	'0xb2': [['-march=armv8.2-a+crc+crypto+lse','-mcpu=octeontx2'], flags_octeontx2_extra],
}
pn_config_emag = {
	'generic': [['-march=armv8-a+crc+crypto', '-mtune=emag']]
}

## Arm implementer ID (ARM DDI 0487C.a, Section G7.2.106, Page G7-5321)
impl_generic = ['Generic armv8', flags_generic, pn_config_default]
impl_0x41 = ['Arm', flags_arm, pn_config_default]
impl_0x42 = ['Broadcom', flags_generic, pn_config_default]
impl_0x43 = ['Cavium', flags_cavium, pn_config_cavium]
impl_0x44 = ['DEC', flags_generic, pn_config_default]
impl_0x49 = ['Infineon', flags_generic, pn_config_default]
impl_0x4d = ['Motorola', flags_generic, pn_config_default]
impl_0x4e = ['NVIDIA', flags_generic, pn_config_default]
impl_0x50 = ['Ampere Computing', flags_emag, pn_config_emag]
impl_0x51 = ['Qualcomm', flags_generic, pn_config_default]
impl_0x53 = ['Samsung', flags_generic, pn_config_default]
impl_0x56 = ['Marvell ARMADA', flags_armada, pn_config_default]
impl_0x69 = ['Intel', flags_generic, pn_config_default]
impl_dpaa = ['NXP DPAA', flags_dpaa, pn_config_default]

dpdk_conf.set('RTE_ARCH_ARM', 1)
dpdk_conf.set('RTE_FORCE_INTRINSICS', 1)

if dpdk_conf.get('RTE_ARCH_32')
	# armv7 build
	dpdk_conf.set('RTE_CACHE_LINE_SIZE', 64)
	dpdk_conf.set('RTE_ARCH_ARMv7', 1)
	# the minimum architecture supported, armv7-a, needs the following,
	# mk/machine/armv7a/rte.vars.mk sets it too
	machine_args += '-mfpu=neon'
else
	# aarch64 build
	if not meson.is_cross_build()
		if machine == 'generic'
			# default build
			impl_config = impl_generic
			part_number = 'generic'
		else
			# native build
			# The script returns ['Implementer', 'Variant', 'Architecture',
			# 'Primary Part number', 'Revision']
			detect_vendor = find_program(join_paths(
					meson.current_source_dir(), 'armv8_machine.py'))
			cmd = run_command(detect_vendor.path())
			if cmd.returncode() == 0
				cmd_output = cmd.stdout().to_lower().strip().split(' ')
			endif
			if arm_force_native_march == true
				part_number = 'native'
			else
				part_number = cmd_output[3]
			endif
			# Set to generic implementer if implementer is not found
			impl_config = get_variable('impl_' + cmd_output[0], 'impl_generic')
		endif
	else
		# cross build
		impl_id = meson.get_cross_property('implementer_id', 'generic')
		part_number = meson.get_cross_property('part_number', 'generic')
		impl_config = get_variable('impl_' + impl_id)
	endif

	message('Arm implementer: ' + impl_config[0])
	message('Arm part number: ' + part_number)

	implementer_flags = impl_config[1]
	part_number_config = impl_config[2]

	if part_number_config.has_key(part_number)
		# use the specified part_number machine args if found
		part_number_config = part_number_config[part_number]
	elif part_number == 'native'
		# use native machine args
		part_number_config = [[native_machine_args]]
	elif not meson.is_cross_build()
		# default to generic machine args if part_number is not found
		# and not forcing native machine args
		# but don't default in cross-builds; if part_number is specified
		# incorrectly in a cross-file, it needs to be fixed there
		part_number_config = part_number_config['generic']
	else
		# cross build and part number is not in part_number_config
		error('Cross build part number 0@0 not found.'.format(part_number))
	endif

	dpdk_flags = flags_common_default + implementer_flags

	if part_number_config.length() > 1
		dpdk_flags += part_number_config[1]
	endif

	# apply cross-specific options
	if meson.is_cross_build()
		# configure RTE_MAX_NUMA_NODES and RTE_MAX_LCORE from cross file
		cross_max_numa_nodes = meson.get_cross_property('max_numa_nodes', 0)
		if cross_max_numa_nodes != 0
			dpdk_flags += [
				['RTE_MAX_NUMA_NODES', cross_max_numa_nodes]
			]
		endif
		cross_max_lcores = meson.get_cross_property('max_lcores', 0)
		if cross_max_lcores != 0
			message('Setting RTE_MAX_LCORE from cross file')
			dpdk_flags += [
				['RTE_MAX_LCORE', cross_max_lcores]
			]
		endif
	endif

	machine_args = [] # Clear previous machine args
	foreach flag: part_number_config[0]
		if cc.has_argument(flag)
			machine_args += flag
		endif
	endforeach

	foreach flag: dpdk_flags
		if flag.length() > 0
			dpdk_conf.set(flag[0], flag[1])
		endif
	endforeach
endif

message('Using machine args: @0@'.format(machine_args))

if (cc.get_define('__ARM_NEON', args: machine_args) != '' or
    cc.get_define('__aarch64__', args: machine_args) != '')
	compile_time_cpuflags += ['RTE_CPUFLAG_NEON']
endif

if cc.get_define('__ARM_FEATURE_CRC32', args: machine_args) != ''
	compile_time_cpuflags += ['RTE_CPUFLAG_CRC32']
endif

if cc.get_define('__ARM_FEATURE_CRYPTO', args: machine_args) != ''
	compile_time_cpuflags += ['RTE_CPUFLAG_AES', 'RTE_CPUFLAG_PMULL',
	'RTE_CPUFLAG_SHA1', 'RTE_CPUFLAG_SHA2']
endif
