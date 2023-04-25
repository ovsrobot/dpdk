# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell International Ltd.

# override default name to drop the hyphen
name = 'test-graph'
cflags += '-Wno-deprecated-declarations'
sources = files(
        'cmdline.c',
        'cmdline_graph.c',
        'parameters.c',
        'testgraph.c',
)

deps += ['ethdev', 'cmdline', 'graph', 'node', 'eal']
