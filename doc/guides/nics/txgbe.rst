..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2015-2020.

TXGBE Poll Mode Driver
======================

The TXGBE PMD (librte_pmd_txgbe) provides poll mode driver support
for Wangxun 10 Gigabit Ethernet NICs.

Features
--------

- Multiple queues for TX and RX
- Receiver Side Scaling (RSS)
- MAC/VLAN filtering
- Packet type information
- Checksum offload
- VLAN/QinQ stripping and inserting
- TSO offload
- Port hardware statistics
- Jumbo frames
- Link state information
- Interrupt mode for RX
- Scattered and gather for TX and RX
- LRO

Prerequisites
-------------

- Learning about Wangxun 10 Gigabit Ethernet NICs using
  `<https://www.net-swift.com/a/383.html>`_.

- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.

Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.

Limitations or Known issues
---------------------------
Build with ICC is not supported yet.
X86-32, Power8, ARMv7 and BSD are not supported yet.
