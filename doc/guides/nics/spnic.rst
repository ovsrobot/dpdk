..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2021 Ramaxel Memory Technology, Ltd


SPNIC Poll Mode Driver
======================

The spnic PMD (**librte_net_spnic**) provides poll mode driver support
for 25Gbps/100Gbps SPNxxx Network Adapters.


Features
--------

- Multiple queues for TX and RX
- Receiver Side Scaling（RSS）
- RSS supports IPv4, IPv6, TCPv4, TCPv6, UDPv4 and UDPv6, use inner type for VXLAN as default
- MAC/VLAN filtering
- Checksum offload
- TSO offload
- LRO offload
- Promiscuous mode
- Port hardware statistics
- Link state information
- Link flow control(pause frame)
- Scattered and gather for TX and RX
- SR-IOV - Partially supported VFIO only
- VLAN filter and VLAN offload
- Allmulticast mode
- MTU update
- Unicast MAC filter
- Multicast MAC filter
- Set Link down or up
- FW version
- Multi arch support: x86_64, ARMv8.

Prerequisites
-------------

- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.


Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.

It is highly recommended to upgrade the spnic driver and firmware to avoid the compatibility issues,
and check the work mode with the latest product documents.

Limitations or Known issues
---------------------------
Build with ICC is not supported yet.
X86-32, Power8, ARMv7 and BSD are not supported yet.
