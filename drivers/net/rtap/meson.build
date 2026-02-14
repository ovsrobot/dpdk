# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Stephen Hemminger

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

liburing = dependency('liburing', version: '>= 2.0', required: false)
if not liburing.found()
    build = false
    reason = 'missing dependency, "liburing"'
endif

if build and not cc.has_header_symbol('linux/io_uring.h', 'IORING_ASYNC_CANCEL_ALL')
    build = false
    reason = 'kernel headers missing IORING_ASYNC_CANCEL_ALL (need kernel >= 5.19 headers)'
endif

sources = files(
        'rtap_ethdev.c',
)

ext_deps += liburing

require_iova_in_mbuf = false
