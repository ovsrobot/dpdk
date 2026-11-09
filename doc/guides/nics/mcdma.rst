..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020-2026 Altera Corporation

MCDMA Poll Mode Driver
======================

The MCDMA PMD (**librte_net_mcdma**) provides poll-mode driver support for
Altera Multi-Channel Direct Memory Access (MCDMA) PCI devices. The driver
exposes host-to-device (H2D) and device-to-host (D2H) descriptor queues as
standard DPDK Ethernet ports and is intended for custom FPGA datapaths where
packet movement is controlled through descriptor rings and queue control/status
registers (QCSR).

The PMD binds to Altera PCI functions (vendor ID ``0x1172``) and maps the
configuration BAR for DMA CSR access. A PIO BAR is optionally mapped for
application-specific control registers in user logic.

Prerequisites
-------------

Follow the DPDK :doc:`/linux_gsg/index` to set up the basic DPDK environment.

The device must be bound to a DPDK-compatible kernel driver such as
``vfio-pci`` or ``igb_uio``.

.. note::

   The MCDMA PMD is supported on Linux only.

Device parameters
-----------------

Device parameters are passed through the EAL ``-a`` allowlist, for example::

   -a 0000:03:00.0,pf_index=0

pf_index
   Physical function index (0–7). When set, the port is treated as a PF and
   PF-only parameters below become available.

parent_pf_idx
   Parent PF index for a virtual function. Required when probing a VF to locate
   channel capacity in the PF configuration registers.

config_bam_bar
   PCI BAR index used for the BAM (bus address mapper) region on a PF. Valid
   values are BAR indices other than the configuration BAR (BAR 0).

vf_weights
   Comma-separated list of 16 VF scheduler weights (1–8). Each weight is
   programmed into the DMA CSR VF weight registers.

Queue model
-----------

Each Ethernet port corresponds to one PCI function (PF or VF). The number of
Rx and Tx queues available is reported through ``rte_eth_dev_info`` and
depends on the IP configuration (up to 512 channels per function).

For each queue the driver allocates:

* A hardware descriptor ring in IOVA-contiguous memory (memzone).
* A software ring tracking in-flight ``rte_mbuf`` pointers.

Descriptor ring size must be a power of two and a multiple of 128 (4096-byte
pages with 32-byte descriptors). The hardware supports up to 65536 descriptors
per ring; the driver accepts at most 32768 (``rte_eth_dev_info`` and queue
setup limits).

H2D queues are used for Tx (``rte_eth_tx_burst()``) and D2H queues for Rx
(``rte_eth_rx_burst()``). Multi-segment mbufs are supported on Tx when
``RTE_ETH_TX_OFFLOAD_MULTI_SEGS`` is enabled. Rx delivers one mbuf per
completed packet; the driver uses an mbuf dynamic field to track
start-of-frame and end-of-frame descriptor flags internally.

Queues can be started and stopped independently, and Rx/Tx queue setup is
supported while the device is running
(``RTE_ETH_DEV_CAPA_RUNTIME_RX_QUEUE_SETUP`` and
``RTE_ETH_DEV_CAPA_RUNTIME_TX_QUEUE_SETUP``).

Link and statistics
-------------------

Link status is only partially supported. ``link_update`` always reports the
port as up and full duplex; there is no carrier detection, link-down state,
or link speed reporting. Applications can call ``rte_eth_link_get()``, but the
returned values are fixed stubs rather than hardware link state.

Port and per-queue statistics are maintained in software and augmented with
hardware drop and pointer-error counters read from QCSR. Use
``rte_eth_stats_get()`` to retrieve them.

Limitations
-----------

The MCDMA PMD is a DMA channel driver rather than a full Ethernet NIC PMD.
The following standard ethdev features are not implemented:

* MAC address programming, promiscuous mode, and multicast filtering.
* RSS, ``rte_flow``, and interrupt-driven Rx/Tx.
* Checksum, TSO, VLAN, and other L2/L3 hardware offloads.
* ``stats_reset`` and extended statistics (xstats).

Traffic acceptance and any Ethernet semantics beyond descriptor DMA are
defined by the FPGA application connected to the MCDMA IP.

Building and testing
--------------------

Refer to :doc:`build_and_test` for general PMD build instructions. Enable the
driver in the Meson build (``-Denable_drivers=net/mcdma`` or a full default
driver build).

The driver has been tested with `DPDK pktgen <https://github.com/pktgen/Pktgen-DPDK>`_.
It has not been tested with testpmd.

Example: pktgen on a bound MCDMA device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Bind the PCI function and start pktgen with one port mapped to a logical core::

   # ./pktgen -l 0-1 -n 4 -a 0000:03:00.0 -- -P -m 1.0

Use the pktgen interactive commands to configure packet size, rate, and
forwarding. Port statistics are shown in the pktgen UI.

For PF-specific setup (VF weights, BAM BAR), add the corresponding allowlist
options to the EAL command line.
