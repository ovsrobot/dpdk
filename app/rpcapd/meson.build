# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

# relies on primary/secondary process, so Linux only
if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

if not dpdk_conf.has('RTE_HAS_LIBPCAP')
    build = false
    reason = 'missing dependency, "libpcap"'
    subdir_done()
endif

# password authentication uses crypt(3)
libcrypt_dep = cc.find_library('crypt', required: false)
if not libcrypt_dep.found()
    build = false
    reason = 'missing dependency, "libcrypt"'
    subdir_done()
endif

sources = files(
        'capture.c',
        'filter.c',
        'main.c',
        'session.c',
        'sock.c',
        'tls.c',
)
ext_deps += pcap_dep
ext_deps += libcrypt_dep
deps += ['ethdev', 'pdump', 'bpf', 'pcapng']

# TLS support is optional; tls.c builds as stubs without it
if dpdk_conf.has('RTE_HAS_OPENSSL')
    ext_deps += openssl_dep
endif
