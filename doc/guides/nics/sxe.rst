..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (C), 2022, Linkdata Technology Co., Ltd.

SXE Poll Mode Driver
======================

The SXE PMD (librte_pmd_sxe) provides poll mode driver support
for Linkdata 1160-2X 10GE Ethernet Adapter.

Features
--------
- PXE boot
- PTP(Precision Time Protocol)
- VMDq(Virtual Machine Device Queues)
- SR-IOV,max 2PF,63VF per PF
- 128 L2 Ethernet MAC Address Filters (unicast and multicast)
- 64 L2 VLAN filters
- pldm over mctp over smbus
- 802.1q VLAN
- Low Latency Interrupts
- LRO
- Promiscuous mode
- Multicast mode
- Multiple queues for TX and RX
- Receiver Side Scaling (RSS)
- MAC/VLAN filtering
- Packet type information
- Checksum offload
- VLAN/QinQ stripping and inserting
- TSO offload
- Port hardware statistics
- Link state information
- Link flow control
- Interrupt mode for RX
- Scattered and gather for TX and RX
- DCB
- IEEE 1588
- FW version
- Generic flow API

Configuration
-------------

Dynamic Logging Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~

One may leverage EAL option "--log-level" to change default levels
for the log types supported by the driver. The option is used with
an argument typically consisting of two parts separated by a colon.

SXE PMD provides the following log types available for control:

- ``pmd.net.sxe.drv`` (default level is **INFO**)

  Affects driver-wide messages unrelated to any particular devices.

- ``pmd.net.sxe.init`` (default level is **INFO**)

  Extra logging of the messages during PMD initialization.

- ``pmd.net.sxe.rx`` (default level is **INFO**)

  Affects rx-wide messages.
- ``pmd.net.sxe.tx`` (default level is **INFO**)

  Affects tx-wide messages.

------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.
