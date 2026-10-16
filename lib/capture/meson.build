# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

# The RCU used by the receive and transmit callbacks needs the OS to be able
# to force a barrier on every CPU running a thread of the process.
# Linux has no libc wrapper, so the syscall number is what matters there;
# FreeBSD has a real membarrier().
if is_linux
    has_membarrier = (cc.has_header_symbol('sys/syscall.h', 'SYS_membarrier')
            and cc.has_header_symbol('linux/membarrier.h',
                'MEMBARRIER_CMD_PRIVATE_EXPEDITED'))
else
    has_membarrier = cc.has_header_symbol('sys/membarrier.h', 'membarrier')
endif
if not has_membarrier
    build = false
    reason = 'missing membarrier support'
    subdir_done()
endif

sources = files(
        'capture.c',
        'datapath.c',
        'multiproc.c',
        'output.c',
        'rcu.c',
)

deps += ['ethdev', 'pcapng', 'bpf']

if dpdk_conf.has('RTE_HAS_LIBPCAP')
    sources += files('filter.c')
    ext_deps += pcap_dep
else
    warning('libpcap is missing, capture filtering will be disabled')
endif
