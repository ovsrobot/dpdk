.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2025 Huawei Technologies Co., Ltd

HINIC3 Poll Mode Driver
=======================

The hinic3 PMD (**librte_net_hinic3**) provides poll mode driver support
for 25Gbps/100Gbps/200Gbps/400Gbps Huawei SP230, SP560 and SP620 series Network Adapters.


Features
--------

- Multi arch support: x86_64, ARMv8.
- Multiple queues for TX and RX
- Receiver Side Scaling (RSS)
- Flow filtering
- Checksum offload
- VLAN/QinQ stripping and inserting
- TSO offload
- Promiscuous mode
- Port hardware statistics
- Jumbo frames
- Link state information
- Link flow control
- Scattered and gather for TX and RX
- Allmulticast mode
- MTU update
- Multicast MAC filter
- NUMA support
- Generic Flow API
- Set Link down or up
- VLAN filter and VLAN offload
- SR-IOV - Partially supported at this point, VFIO only
- FW version
- LRO


Prerequisites
-------------

- Follow the DPDK :doc:`/linux_gsg/index` to setup the basic DPDK environment.


Driver compilation and testing
------------------------------

Refer to the document :doc:`build_and_test` for details.


Runtime Configuration
---------------------

The driver can be configured at initialization via EAL device parameters.
The following parameters are supported:

- ``tx_pending_limit`` (default **2**): TX completion index coalescing
  pending limit.

- ``tx_coalescing_time`` (default **2**): TX completion index coalescing
  time.

- ``rx_cqe_compact_en`` (default **1**): enable (``1``) or disable (``0``)
  compact CQE mode.

- ``rx_cqe_coalesce_num`` (default **7**): RX CQE coalescing count.

- ``rx_cqe_timer_loop`` (default **8**): RX CQE coalescing timer loop.


Limitations or Known issues
---------------------------

x86-32, Windows, and BSD are not supported yet.
