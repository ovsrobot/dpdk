# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Marvell

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

if is_linux
    sources += files('virtio_user/vhost_vdpa.c')
    deps += ['bus_vdev']
endif
