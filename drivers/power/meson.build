# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Advanced Micro Devices, Inc.

drivers = [
        'acpi',
        'amd_pstate',
        'amd_uncore',
        'cppc',
        'intel_pstate',
        'intel_uncore',
        'kvm_vm',
]

std_deps = ['power']

extra_flags = ['-Wvla']

foreach arg: extra_flags
    if cc.has_argument(arg)
        cflags += arg
    endif
endforeach
