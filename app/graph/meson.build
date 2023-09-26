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
        'ethdev_rx.c',
        'ethdev.c',
        'ip4_route.c',
        'ip6_route.c',
        'main.c',
        'mempool.c',
        'neigh.c',
        'utils.c',
)
