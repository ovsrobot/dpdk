..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 ZTE Corporation.


ZXDH Poll Mode Driver
======================

The ZXDH PMD (**librte_net_zxdh**) provides poll mode driver support
for 25/100 Gbps ZXDH NX Series Ethernet Controller based on
the ZTE Ethernet Controller E310/E312.


Features
--------

Features of the zxdh PMD are:

- Multi arch support: x86_64, ARMv8.
- Multiple queues for TX and RX
- Receiver Side Scaling (RSS)
- MAC/VLAN filtering
- Checksum offload
- TSO offload
- VLAN/QinQ stripping and inserting
- Promiscuous mode
- Port hardware statistics
- Link state information
- Link flow control
- Scattered and gather for TX and RX
- SR-IOV VF
- VLAN filter and VLAN offload
- Allmulticast mode
- MTU update
- Jumbo frames
- Unicast MAC filter
- Multicast MAC filter
- Flow API
- Set Link down or up
- FW version
- LRO

Prerequisites
-------------

This PMD driver need NPSDK library for system initialization and allocation of resources.
Communication between PMD and kernel modules is mediated by zxdh Kernel modules.
The NPSDK library and zxdh Kernel modules are not part of DPDK and must be installed
separately:

- Getting the latest NPSDK library and software supports using
  ``_.

Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.

Limitations or Known issues
---------------------------
X86-32, Power8, ARMv7 and BSD are not supported yet.
