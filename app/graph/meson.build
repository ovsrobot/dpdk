# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 Marvell.

# override default name to drop the hyphen
name = 'graph'
if not build
    subdir_done()
endif

deps += ['bus_pci', 'graph', 'eal', 'lpm', 'ethdev', 'node', 'cmdline']
sources = files(
        'cli.c',
        'conn.c',
        'main.c',
        'utils.c',
)
