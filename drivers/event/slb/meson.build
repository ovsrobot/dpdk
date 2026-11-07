# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files(
        'slb_evdev.c',
        'slb_event.c',
)

deps += ['bus_vdev', 'ring']
