# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2024 AMD Limited.
#

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

sources = files(
        'guest_channel.c',
        'power_kvm_vm.c',
)

headers = files(
        'guest_channel.h',
        'power_kvm_vm.h',
)
deps += ['power']
