# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

if not dpdk_conf.get('RTE_ARCH_64')
    error('Only 64-bit compiles are supported for this platform type')
endif
dpdk_conf.set('RTE_ARCH', 'ppc_64')
dpdk_conf.set('RTE_ARCH_PPC_64', 1)

# Checking compiler for supporting Power CPU platform
# For newer Power(N) System that current gcc may not supoort it yet,
# it falls back and try  N-1 and N-2
check_cpu = find_program(join_paths(meson.current_source_dir(),
		  'check_cpu_platform.sh'))

target_cpu = run_command(check_cpu.path()).stdout().strip()

cpu_int = target_cpu.to_int()
cpu_flag = '-mcpu=power@0@'
tune_flag = '-mtune=power@0@'
machine_type = 'power@0@'
debug = 'configure the compiler to build DPDK for POWER@0@ platform'

if cc.has_argument(cpu_flag.format(cpu_int))

  # target system cpu is supported by the compiler, use '-mcpu=native'
  message(debug.format(target_cpu+'_native'))
  machine_args = ['-mcpu=native']
  dpdk_conf.set('RTE_MACHINE',machine_type.format(cpu_int))
elif cc.has_argument(cpu_flag.format(cpu_int-1))
  message(debug.format(cpu_int-1))
  machine_args = [cpu_flag.format(cpu_int-1),tune_flag.format(cpu_int-1)]
  dpdk_conf.set('RTE_MACHINE',machine_type.format(cpu_int-1))
elif cc.has_argument(cpu_flag.format(cpu_int-2))
  message(debug.format(cpu_int-2))
  machine_args = [cpu_flag.format(cpu_int-2),tune_flag.format(cpu_int-2)]
  dpdk_conf.set('RTE_MACHINE',machine_type.format(cpu_int-2))
else
  error('The compiler does not support POWER@0@ platform' .format(cpu_int))
endif



# Certain POWER9 systems can scale as high as 1536 LCORES, but setting such a
# high value can waste memory, cause timeouts in time limited autotests, and is
# unlikely to be used in many production situations.  Similarly, keeping the
# default 64 LCORES seems too small as most POWER9 dual socket systems will have
# at least 128 LCORES available.  Set RTE_MAX_LCORE to 128 for POWER systems as
# a compromise.
dpdk_conf.set('RTE_MAX_LCORE', 128)

# POWER systems do not allocate NUMA nodes sequentially.  A dual socket system
# will have CPUs associated with NUMA nodes 0 & 8, so ensure that the second
# NUMA node will be supported by setting RTE_MAX_NUMA_NODES to 16. High end
# systems can scale even higher with as many as 32 NUMA nodes.
dpdk_conf.set('RTE_MAX_NUMA_NODES', 16)

dpdk_conf.set('RTE_CACHE_LINE_SIZE', 128)
