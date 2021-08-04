.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2021 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 21.08
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      make doc-guides-html
      xdg-open build/doc/html/guides/rel_notes/release_21_08.html


New Features
------------

.. This section should contain new features added in this release.
   Sample format:

   * **Add a title in the past tense with a full stop.**

     Add a short 1-2 sentence description in the past tense.
     The description should be enough to allow someone scanning
     the release notes to understand the new feature.

     If the feature adds a lot of sub-features you can use a bullet list
     like this:

     * Added feature foo to do something.
     * Enhanced feature bar to do something else.

     Refer to the previous release notes for examples.

     Suggested order in release notes items:
     * Core libs (EAL, mempool, ring, mbuf, buses)
     * Device abstraction libs and PMDs (ordered alphabetically by vendor name)
       - ethdev (lib, PMDs)
       - cryptodev (lib, PMDs)
       - eventdev (lib, PMDs)
       - etc
     * Other libs
     * Apps, Examples, Tools (if significant)

     This section is a comment. Do not overwrite or remove it.
     Also, make sure to start the actual text at the margin.
     =======================================================

* **Added auxiliary bus support.**

  Auxiliary bus provides a way to split function into child-devices
  representing sub-domains of functionality. Each auxiliary device
  represents a part of its parent functionality.

* **Added XZ compressed firmware support.**

  Using ``rte_firmware_read``, a driver can now handle XZ compressed firmware
  in a transparent way, with EAL uncompressing using libarchive if this library
  is available when building DPDK.

* **Updated Amazon ENA PMD.**

  The new driver version (v2.4.0) introduced bug fixes and improvements,
  including:

  * Added Rx interrupt support.
  * RSS hash function key reconfiguration support.

* **Updated Intel iavf driver.**

  * Added Tx QoS VF queue TC mapping.
  * Added FDIR and RSS for GTPoGRE, support filter based on GTPU TEID/QFI,
    outer most L3 or inner most l3/l4. 

* **Updated Intel ice driver.**

  * In AVX2 code, added the new RX and TX paths to use the HW offload
    features. When the HW offload features are configured to be used, the
    offload paths are chosen automatically. In parallel the support for HW
    offload features was removed from the legacy AVX2 paths.
  * Added Tx QoS TC bandwidth configuration in DCF.

* **Added support for Marvell CN10K SoC ethernet device.**

  * Added net/cnxk driver which provides the support for the integrated ethernet
    device.

* **Updated Mellanox mlx5 driver.**

  * Added Sub-Function support based on auxiliary bus.
  * Added support for meter hierarchy.
  * Added support for metering policy actions of yellow color.
  * Added support for metering trTCM RFC2698 and RFC4115.
  * Added devargs options ``allow_duplicate_pattern``.
  * Added matching on IPv4 Internet Header Length (IHL).
  * Added support for matching on VXLAN header last 8-bits reserved field.
  * Optimized multi-thread flow rule insertion rate.

* **Added Wangxun ngbe PMD.**

  Added a new PMD driver for Wangxun 1 Gigabit Ethernet NICs.
  See the :doc:`../nics/ngbe` for more details.

* **Updated Solarflare network PMD.**

  Updated the Solarflare ``sfc_efx`` driver with changes including:

  * Added COUNT action support for SN1000 NICs

* **Added inflight packets clear API in vhost library.**

  Added an API which can clear the inflight packets submitted to DMA
  engine in vhost async data path.

* **Updated Intel QuickAssist crypto PMD.**

  Added fourth generation of QuickAssist Technology(QAT) devices support.
  Only symmetric crypto has been currently enabled, compression and asymmetric
  crypto PMD will fail to create.

* **Added support for Marvell CNXK crypto driver.**

  * Added cnxk crypto PMD which provides support for an integrated
    crypto driver for CN9K and CN10K series of SOCs. Support for
    symmetric crypto algorithms is added to both the PMDs.
  * Added support for lookaside protocol (IPsec) offload in cn10k PMD.
  * Added support for asymmetric crypto operations in cn9k and cn10k PMD.

* **Updated Marvell OCTEON TX crypto PMD.**

  Added support for crypto adapter OP_FORWARD mode.

* **Added support for Nvidia crypto device driver.**

  Added mlx5 crypto driver to support AES-XTS cipher operations.
  The first device to support it is ConnectX-6.

* **Updated ISAL compress device PMD.**

  The ISAL compress device PMD now supports Arm platforms.

* **Added Baseband PHY CNXK PMD.**

  Added Baseband PHY PMD which allows to configure BPHY hardware block
  comprising accelerators and DSPs specifically tailored for 5G/LTE inline
  use cases. Configuration happens via standard rawdev enq/deq operations. See
  the :doc:`../rawdevs/cnxk_bphy` rawdev guide for more details on this driver.

* **Added support for Marvell CN10K, CN9K, event Rx/Tx adapter.**

  * Added Rx/Tx adapter support for event/cnxk when the ethernet device requested
    is net/cnxk.
  * Added support for event vectorization for Rx/Tx adapter.

* **Added cppc_cpufreq support to Power Management library.**

  Added support for cppc_cpufreq driver which works on most arm64 platforms.

* **Added multi-queue support to Ethernet PMD Power Management**

  The experimental PMD power management API now supports managing
  multiple Ethernet Rx queues per lcore.

* **Updated testpmd to log errors to stderr.**

  Updated testpmd application to log errors and warnings to stderr
  instead of stdout used before.


Removed Items
-------------

.. This section should contain removed items in this release. Sample format:

   * Add a short 1-2 sentence description of the removed item
     in the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================


API Changes
-----------

.. This section should contain API changes. Sample format:

   * sample: Add a short 1-2 sentence description of the API change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* eal: ``rte_strscpy`` sets ``rte_errno`` to ``E2BIG`` in case of string
  truncation.

* eal: ``rte_bsf32_safe`` now takes a 32-bit value for its first argument.
  This fixes warnings about loss of precision
  when used with some compilers settings.

* eal: ``rte_power_monitor`` and the ``rte_power_monitor_cond`` struct changed
  to use a callback mechanism.

* rte_power: The experimental PMD power management API is no longer considered
  to be thread safe; all Rx queues affected by the API will now need to be
  stopped before making any changes to the power management scheme.


ABI Changes
-----------

.. This section should contain ABI changes. Sample format:

   * sample: Add a short 1-2 sentence description of the ABI change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* No ABI change that would break compatibility with 20.11.


Known Issues
------------

.. This section should contain new known issues in this release. Sample format:

   * **Add title in present tense with full stop.**

     Add a short 1-2 sentence description of the known issue
     in the present tense. Add information on any known workarounds.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================


Tested Platforms
----------------

.. This section should contain a list of platforms that were tested
   with this release.

   The format is:

   * <vendor> platform with <vendor> <type of devices> combinations

     * List of CPU
     * List of OS
     * List of devices
     * Other relevant details...

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* Intel\ |reg| platforms with Mellanox\ |reg| NICs combinations

  * CPU:

    * Intel\ |reg| Xeon\ |reg| Gold 6154 CPU @ 3.00GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2697A v4 @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2697 v3 @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2680 v2 @ 2.80GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2670 0 @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2650 v4 @ 2.20GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2650 v3 @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2640 @ 2.50GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2650 0 @ 2.00GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2620 v4 @ 2.10GHz

  * OS:

    * Red Hat Enterprise Linux release 8.2 (Ootpa)
    * Red Hat Enterprise Linux Server release 7.8 (Maipo)
    * Red Hat Enterprise Linux Server release 7.6 (Maipo)
    * Red Hat Enterprise Linux Server release 7.5 (Maipo)
    * Red Hat Enterprise Linux Server release 7.4 (Maipo)
    * Red Hat Enterprise Linux Server release 7.3 (Maipo)
    * Red Hat Enterprise Linux Server release 7.2 (Maipo)
    * Ubuntu 20.04
    * Ubuntu 18.04
    * Ubuntu 16.04
    * SUSE Enterprise Linux 15 SP2
    * SUSE Enterprise Linux 12 SP4

  * OFED:

    * MLNX_OFED 5.4-1.0.3.0 and above
    * MLNX_OFED 5.3-1.0.0.1

  * upstream kernel:

    * Linux 5.14.0-rc3 and above

  * rdma-core:

    * rdma-core-36.0 and above

  * NICs:

    * Mellanox\ |reg| ConnectX\ |reg|-3 Pro 40G MCX354A-FCC_Ax (2x40G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1007
      * Firmware version: 2.42.5000

    * Mellanox\ |reg| ConnectX\ |reg|-3 Pro 40G MCX354A-FCCT (2x40G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1007
      * Firmware version: 2.42.5000

    * Mellanox\ |reg| ConnectX\ |reg|-4 Lx 25G MCX4121A-ACAT (2x25G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1015
      * Firmware version: 14.31.1014 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 Lx 50G MCX4131A-GCAT (1x50G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1015
      * Firmware version: 14.31.1014 and above

    * Mellanox\ |reg| ConnectX\ |reg|-5 100G MCX516A-CCAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.31.1014 and above

    * Mellanox\ |reg| ConnectX\ |reg|-5 100G MCX556A-ECAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.31.1014 and above

    * Mellanox\ |reg| ConnectX\ |reg|-5 100G MCX556A-EDAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.31.1014 and above

    * Mellanox\ |reg| ConnectX\ |reg|-5 Ex EN 100G MCX516A-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:1019
      * Firmware version: 16.31.1014 and above

    * Mellanox\ |reg| ConnectX\ |reg|-6 Dx EN 100G MCX623106AN-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:101d
      * Firmware version: 22.31.1014 and above

    * Mellanox\ |reg| ConnectX\ |reg|-6 Lx EN 25G MCX631102AN-ADAT (2x25G)

      * Host interface: PCI Express 4.0 x8
      * Device ID: 15b3:101f
      * Firmware version: 26.31.1014 and above

* Mellanox\ |reg| BlueField\ |reg| SmartNIC

  * Mellanox\ |reg| BlueField\ |reg| 2 SmartNIC MT41686 - MBF2H332A-AEEOT_A1 (2x25G)

    * Host interface: PCI Express 3.0 x16
    * Device ID: 15b3:a2d6
    * Firmware version: 24.31.1014 and above

  * Embedded software:

    * CentOS Linux release 7.6.1810 (AltArch)
    * MLNX_OFED 5.4-1.0.3.0 and above
    * DPDK application running on Arm cores
