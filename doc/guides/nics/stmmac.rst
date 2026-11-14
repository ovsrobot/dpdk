..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2026 Qualcomm Technologies, Inc.

Stmmac Poll Mode Driver
=======================

The stmmac PMD (**librte_net_stmmac**) provides poll mode driver
support for the Synopsys DesignWare Cores Enhanced Quality-of-Service
(DWC EQoS / GMAC4) Ethernet MAC present on Qualcomm SoCs such as the
IQ9075 (QCS9075) found on the Shikra EVK platform.

More information on the Qualcomm Shikra platform can be found at
`Qualcomm Developer Network <https://www.qualcomm.com/developer>`_.

Synopsys DWC EQoS (GMAC4, "stmmac")
-------------------------------------

This section provides an overview of the Synopsys DWC EQoS MAC
architecture and how it is integrated into DPDK.

Contents summary

- DWC EQoS overview
- Driver architecture overview
- Device configuration and devargs

.. _stmmac_overview:

DWC EQoS Overview
~~~~~~~~~~~~~~~~~~

The Synopsys DesignWare Cores Enhanced Quality-of-Service (DWC EQoS)
is a fully integrated 10/100/1000 Mb/s Ethernet MAC core. The "stmmac"
name follows the Linux kernel driver family
(``drivers/net/ethernet/stmicro/stmmac``).

The MAC core revision used on the Qualcomm Shikra EVK is GMAC4 v5.30a.

DWC EQoS includes:

- MAC core (GMAC4): frame transmission, reception, MDIO management,
  address filtering, and hardware checksum offload
- MTL (MAC Transaction Layer): configurable TX/RX FIFOs with
  store-and-forward mode; FIFO sizes are read from HW_FEATURE1 at probe
- DMA engine: AXI system bus with fixed burst, mixed burst, AAL and
  EAME (>4 GiB IOVA support); per-channel burst (PBL 32, PBLx8, OSP)
- RGMII IO macro: Qualcomm-specific SerDes block for RGMII-ID timing

The Network and packet I/O component:

- One DMA channel (channel 0) with one TX queue and one RX queue.
  The PMD operates DMA channel 0 exclusively.
- The DMA is not cache-coherent on the Shikra platform. The PMD
  performs explicit DC CVAC/CIVAC cache maintenance on arm64 for both
  descriptor lines and packet payload. No-op stubs are provided for
  other architectures.

Stmmac DPDK - Poll Mode Driver Overview
-----------------------------------------

This section provides an overview of the stmmac PMD for DPDK.

The PMD is probed by the DPDK platform bus and uses ``vfio-platform``
for MMIO access and DMA mapping. The kernel recovery driver must be
loaded first to perform clock enable and PHY reset; the PMD then takes
over and must not be unloaded while the PMD is running.

.. code-block:: console

                            +-------------------+
                            |  DPDK Application |
                            +--------+----------+
                                     |
                            +--------+----------+
                            |  stmmac PMD       |
                            | (librte_net_stmmac)|
                            +----+----------+---+
                                 |          |
                       +---------+--+   +---+---------+
                       | TX Burst   |   | RX Burst    |
                       | (DMA ch 0) |   | (DMA ch 0)  |
                       +---------+--+   +---+---------+
                                 |          |
              ===================|==========|================ HARDWARE
                            +----+----------+---+
                            |  DWC EQoS (GMAC4) |
                            |  MAC / MTL / DMA   |
                            +--------+----------+
                                     |
                            +--------+----------+
                            |  RGMII IO Macro   |
                            +--------+----------+
                                     |
                            +--------+----------+
                            |  DP83867 PHY      |
                            +-------------------+

Platform Bus Driver
~~~~~~~~~~~~~~~~~~~

The stmmac PMD registers as an ``rte_platform_driver``. The platform bus
scans the kernel sysfs tree for a device whose driver alias matches
``vfio-platform``. Two MMIO resources are consumed:

- ``resource[0]``: MAC/MTL/DMA register block (``stmmaceth`` in DT)
- ``resource[1]``: RGMII IO macro register block (``rgmii`` in DT)

The kernel ``vfio-platform`` driver must be bound to the stmmac device
before launching a DPDK application.

Stmmac NIC Driver (PMD)
~~~~~~~~~~~~~~~~~~~~~~~~~

The stmmac PMD implements the standard DPDK ethdev API for the DWC EQoS
MAC. It directly programs the MAC, MTL and DMA register blocks over
the MMIO mapping provided by vfio-platform.

- On probe, the PMD reads devargs, maps MMIO resources, sets RGMII IO
  macro timing, programs DP83867 RGMII internal delays via MMD indirect
  access, and registers the ethdev.
- On ``dev_start``, the PMD enables the RGMII functional clock,
  performs a DMA soft reset, programs AXI sysbus and per-channel burst
  settings, sets up TX and RX descriptor rings, initialises the MAC
  and MTL, and starts DMA.
- Link state is polled from the DP83867 PHY using IEEE 802.3 clause-22
  MDIO. BMSR is double-read to clear the latched link bit; live speed
  and duplex come from PHYSTS.

Features
^^^^^^^^

Features of the stmmac PMD are:

- Single TX queue and single RX queue on DMA channel 0
- IPv4, TCP and UDP hardware checksum offload (TX and RX)
- Promiscuous mode
- MAC address set
- Link state update via DP83867 PHY MDIO (clause-22)
- Per-queue packet and byte counters (stats_get / stats_reset)
- Configurable ring sizes (64..1024 descriptors, multiples of 4)
- Non-coherent DMA support (arm64 DC CVAC/CIVAC cache maintenance)
- 36-bit DMA addressing (EAME enabled, mbufs above 4 GiB supported)

Allowing & Blocking
-------------------

To block a stmmac device from being used by DPDK, the following EAL
argument can be used:

.. code-block:: console

   <dpdk app> <EAL args> -b "platform:<device_name>" -- ...
   e.g. -b "platform:a000000.ethernet"

Supported Platforms
-------------------

- Qualcomm IQ9075 (QCS9075) — Shikra EVK (arm64)

Prerequisites
-------------

- Follow the DPDK :doc:`/linux_gsg/index` to set up the basic DPDK
  environment.
- An arm64 cross-compilation toolchain is required to build for the
  Shikra EVK target from an x86 host.
- The kernel ``vfio-platform`` and ``vfio_iommu_type1`` modules must be
  loaded on the target before launching a DPDK application.
- The Qualcomm stmmac recovery kernel driver must be loaded first to
  enable clocks and reset the PHY. The PMD does not perform these steps.

.. note::

   The stmmac PMD is supported on Linux only. It requires the platform
   bus (``rte_bus_platform``) and ``vfio-platform`` kernel support.

Configuration
-------------

Devargs
~~~~~~~

The stmmac PMD accepts the following device arguments:

.. list-table:: stmmac devargs
   :header-rows: 1
   :widths: 20 10 70

   * - Parameter
     - Default
     - Description
   * - ``has_emac_ge_3``
     - ``1``
     - DMA/MTL channel stride override. Set to ``1`` for EMAC >= 3.0
       platforms (Shikra IQ9075), which use a 0x1000 channel stride
       (base 0x8100 for DMA, 0x8000 for MTL). Set to ``0`` for
       generic dwmac4 layout (base 0x1100, stride 0x80).
   * - ``mdio_addr``
     - ``7``
     - PHY MDIO address. The DP83867 on the Shikra EVK is at address 7.
       Override if the PHY is at a different address.

Example devarg usage:

.. code-block:: console

   --dev "platform:a000000.ethernet,has_emac_ge_3=1,mdio_addr=7"

Driver Compilation and Testing
-------------------------------

Refer to the document :doc:`build_and_test` for details.

#. Cross-compile for arm64 (from an x86 host):

   .. code-block:: console

      meson setup build-arm64 \
          --cross-file config/arm/arm64_armv8_linux_gcc \
          -Dplatform=generic
      ninja -C build-arm64

#. Bind the device to ``vfio-platform`` on the target:

   .. code-block:: console

      # Load required kernel modules
      modprobe vfio
      modprobe vfio-platform
      modprobe vfio_iommu_type1

      # Identify the device name from sysfs
      ls /sys/bus/platform/devices/ | grep ethernet
      # e.g. a000000.ethernet

      # Bind to vfio-platform
      echo vfio-platform > /sys/bus/platform/devices/a000000.ethernet/driver_override
      echo a000000.ethernet > /sys/bus/platform/drivers/vfio-platform/bind

      # Verify the bind succeeded
      ls /sys/bus/platform/devices/a000000.ethernet/driver
      # Should show: .../vfio-platform

#. Running testpmd on the Shikra EVK:

   .. code-block:: console

      ./<build_dir>/app/dpdk-testpmd \
          -l 0-3 -n 1 --vdev="" \
          -- -i --portmask=0x1 --nb-cores=1 --no-flush-rx
      .....
      EAL: Registered [platform] bus.
      EAL: Detected 8 lcore(s)
      .....
      Configuring Port 0 (socket 0)
      Port 0: 02:02:02:02:02:02
      .....
      Checking link statuses...
      Port 0 Link Up - speed 1000 Mbps - full-duplex
      Done
      testpmd>

   * Use devarg ``has_emac_ge_3=0`` for non-Shikra platforms with the
     generic dwmac4 DMA channel layout.
   * Use devarg ``mdio_addr=<n>`` if the PHY MDIO address differs from
     the Shikra default of 7.

Limitations
-----------

Single Queue
~~~~~~~~~~~~

The stmmac PMD supports one TX queue and one RX queue only (DMA
channel 0). Multi-queue configurations are not supported in this
release.

Single-segment Mbufs
~~~~~~~~~~~~~~~~~~~~~

Only single-segment mbufs are supported. Scatter-gather, TSO, jumbo
frames, and multi-segment packet transmission are not supported. The
application must ensure that ``nb_segs == 1`` for every transmitted
mbuf.

No Interrupt Support
~~~~~~~~~~~~~~~~~~~~~

The PMD is polling-only. No interrupt-driven TX completion or RX
notification is supported. The platform bus does not expose an interrupt
to the PMD.

No Secondary Process Support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Multi-process operation where I/O is performed by a secondary DPDK
process is not supported.

Platform Requirement
~~~~~~~~~~~~~~~~~~~~~

The stmmac PMD is supported on Linux on arm64 only. It has been tested
on the Qualcomm Shikra EVK (IQ9075 / QCS9075 SoC). Operation on other
platforms is not guaranteed.
