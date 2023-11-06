# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022-2023 University of New Hampshire
# Copyright(c) 2023 PANTHEON.tech s.r.o.

"""Testbed modelling.

This package defines the testbed elements DTS works with:

    * A system under test node: :class:`SutNode`,
    * A traffic generator node: :class:`TGNode`,
    * The ports of network interface cards (NICs) present on nodes: :class:`Port`,
    * The logical cores of CPUs present on nodes: :class:`LogicalCore`,
    * The virtual devices that can be created on nodes: :class:`VirtualDevice`,
    * The operating systems running on nodes: :class:`LinuxSession` and :class:`PosixSession`.

DTS needs to be able to connect to nodes and understand some of the hardware present on these nodes
to properly build and test DPDK.
"""

# pylama:ignore=W0611

from .cpu import LogicalCoreCount, LogicalCoreCountFilter, LogicalCoreList
from .node import Node
from .port import Port, PortLink
from .sut_node import SutNode
from .tg_node import TGNode
from .virtual_device import VirtualDevice
