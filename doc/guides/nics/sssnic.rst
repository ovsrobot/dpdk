..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2022 Shenzhen 3SNIC Information Technology Co., Ltd.

SSSNIC Poll Mode Driver
=======================

The sssnic PMD (**librte_pmd_sssnic**) provides poll mode driver support
for 3SNIC 9x0 serials family of Ethernet adapters.


Supported NICs
--------------

- 3S910 Dual Port SFP28 10/25GbE Ethernet adapter
- 3S920 Quad Port SFP28 10/25GbE Ethernet adapter
- 3S920 Quad Port QSFP28 100GbE Ethernet adapter


Features
--------

Features of sssnic PMD are:

- Link status
- Link status event
- Queue start/stop
- Rx interrupt
- Scattered Rx
- TSO
- LRO
- Promiscuous mode
- Allmulticast mode
- Unicast MAC filter
- Multicast MAC filte
- RSS hash
- RSS key update
- RSS reta update
- Inner RSS
- VLAN filter
- VLAN offload
- L3 checksum offload
- L4 checksum offload
- Inner L3 checksum
- Inner L4 checksum
- Basic stats
- Extended stats
- Stats per queue
- Flow control
- FW version
- Generic flow API


Prerequisites
-------------

- Learning about 3SNIC Ethernet NICs using
  `<https://www.3snic.com/products/SSSNIC>`_.

- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.


Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.


Limitations or Known issues
---------------------------

Build with ICC is not supported yet.
Power8, ARMv7 and BSD are not supported yet.
