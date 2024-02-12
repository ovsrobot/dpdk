# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Marvell.

if not is_linux
    build = false
    reason = 'only supported on Linux'
endif

nitrox_crypto = true
nitrox_crypto_path = 'crypto/nitrox'
nitrox_crypto_relpath = '../../' + nitrox_crypto_path

if disable_drivers.contains(nitrox_crypto_path)
    nitrox_crypto = false
endif

deps += ['bus_pci', 'cryptodev']
sources = files(
        'nitrox_device.c',
        'nitrox_hal.c',
        'nitrox_logs.c',
        'nitrox_qp.c',
)
includes += include_directories(
        nitrox_crypto_relpath,
)

if nitrox_crypto
    foreach f: ['nitrox_sym.c',
		'nitrox_sym_capabilities.c',
		'nitrox_sym_reqmgr.c',
        ]
        sources += files(join_paths(nitrox_crypto_relpath, f))
    endforeach
endif
