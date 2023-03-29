.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2022 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 23.03
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_23_03.html


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

* **Introduced lock annotations.**

  Added lock annotations attributes so that clang can statically analyze lock
  correctness.

* **Added support for reporting lcore usage in applications.**

  * The ``/eal/lcore/list``, ``/eal/lcore/usage`` and ``/eal/lcore/info``
    telemetry endpoints have been added to provide information similar to
    ``rte_lcore_dump()``.
  * Applications can register a callback at startup via
    ``rte_lcore_register_usage_cb()`` to provide lcore usage information.

* **Added platform bus support.**

  A platform bus provides a way to use Linux platform devices which
  are compatible with vfio-platform kernel driver.

* **Added ARM support for power monitor in the power management library.**

  Added power monitor and wake up API support
  with WFE/SVE instructions for Arm architecture.

* **Added Ethernet link speed for 400 Gb/s.**

* **Added support for mapping a queue with an aggregated port.**

  * Introduced new function ``rte_eth_dev_count_aggr_ports()``
    to get the number of aggregated ports.
  * Introduced new function ``rte_eth_dev_map_aggr_tx_affinity()``
    to map a Tx queue with an aggregated port of the DPDK port.
  * Added Rx affinity flow matching of an aggregated port.

* **Added flow matching of IPv6 routing extension.**

  Added ``RTE_FLOW_ITEM_TYPE_IPV6_ROUTING_EXT``
  to match IPv6 routing extension header fields.

* **Added flow matching of ICMPv6.**

  Added flow items to match ICMPv6 echo request and reply packets.
  Matching patterns can include ICMP identifier and sequence numbers.

* **Added flow flex handle to modify action.**

  Added flex modify item ``RTE_FLOW_FIELD_FLEX_ITEM``.

* **Added index-based rules insertion in flow API.**

  * Added ``rte_flow_table_insertion_type`` to allow the creation
    of index-based template tables in addition to pattern-based tables.
  * Introduced new function ``rte_flow_async_create_by_index()``
    to insert rules by index into index-based template tables.
  * Added hash calculation function used in template tables
    to allow control over the calculation of the rule index for a packet.

* **Added cross-port indirect action in asynchronous flow API.**

  * Allowed to share indirect actions between ports by passing
    the flag ``RTE_FLOW_PORT_FLAG_SHARE_INDIRECT`` to ``rte_flow_configure()``.
  * Added ``host_port_id`` in ``rte_flow_port_attr`` structure
    to reference the port hosting the shared objects.

* **Added atomic query and update indirect flow action.**

  Added synchronous and asynchronous functions to atomically query and update
  indirect flow action:

  * ``rte_flow_action_handle_query_update()``
  * ``rte_flow_async_action_handle_query_update()``

* **Added flow quota action and item.**

  * ``RTE_FLOW_ACTION_TYPE_QUOTA``
  * ``RTE_FLOW_ITEM_TYPE_QUOTA``

* **Added flow API to skip congestion management configuration.**

  * Added the action ``RTE_FLOW_ACTION_TYPE_SKIP_CMAN`` to skip
    congestion management processing
    based on per flow or packet color identified by a flow meter object.

* **Updated AMD axgbe driver.**

  * Added multi-process support.

* **Updated Atomic Rules ark driver.**

  * Added Arkville FX2 device supporting PCIe Gen5x16.

* **Updated Corigine nfp driver.**

  * Added support for meter options.
  * Added support for rte_flow meter action.

* **Added Intel cpfl driver.**

  Added the new cpfl net driver
  for Intel\ |reg| Infrastructure Processing Unit (Intel\ |reg| IPU) E2100.
  See the :doc:`../nics/cpfl` NIC guide for more details on this new driver.

* **Updated Intel igc driver.**

  * Added support for timesync API.
  * Added support for packet pacing (launch time offloading).

* **Updated Marvell cnxk ethdev driver.**

  * Added support to skip RED using ``RTE_FLOW_ACTION_TYPE_SKIP_CMAN``.

* **Updated NVIDIA mlx5 driver.**

  * Added support for matching on ICMPv6 ID and sequence fields.
  * Added support for MPLSoUDP in hardware steering.
  * Added support for enhanced CQE compression layout.

* **Updated Wangxun ngbe driver.**

  * Added chip overheat detection support.

* **Updated Wangxun txgbe driver.**

  * Added chip overheat detection support.
  * Added SFP hot-plug identification support.

* **Added new algorithms to cryptodev.**

  Added SHAKE-128 and SHAKE-256 symmetric secure hash algorithm.

* **Updated Marvell cnxk crypto driver.**

  Added support for SHAKE hash algorithm in cn9k and cn10k.

* **Updated Intel QuickAssist Technology (QAT) crypto driver.**

  * Added support for SHA3 224/256/384/512 plain hash in QAT GEN 3.
  * Added support for SHA3 256 plain hash in QAT GEN 2.
  * Added support for asymmetric crypto in QAT GEN3.

* **Added LZ4 algorithm in compressdev library.**

  Added LZ4 compression algorithm with xxHash-32 for the checksum.

* **Updated NVIDIA mlx5 compress driver.**

  Added LZ4 algorithm support for decompress operation.

* **Added machine learning inference device library.**

  * Added a machine learning inference device framework for management
    and provision of hardware and software machine learning inference devices.
  * Added a test application for machine learning inference device library.

* **Added Marvell CNXK machine learning driver.**

  Added driver which supports machine learning inference operations
  on Marvell's CN10K series of SoC's.

* **Updated the eventdev reconfigure logic for service based adapters.**

  * eventdev reconfig logic is enhanced to increment the
    ``rte_event_dev_config::nb_single_link_event_port_queues`` parameter
    if event port config is of type ``RTE_EVENT_PORT_CFG_SINGLE_LINK``.
  * With this change, the application no longer needs to account for the
    ``rte_event_dev_config::nb_single_link_event_port_queues`` parameter
    required for eth_rx, eth_tx, crypto and timer eventdev adapters.

* **Added pcap trace support in graph library.**

  * Added support to capture packets at each graph node with packet metadata and
    node name.


Removed Items
-------------

.. This section should contain removed items in this release. Sample format:

   * Add a short 1-2 sentence description of the removed item
     in the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* Removed the experimental empty poll API from the power management library.

  The empty poll mechanism is superseded by the power PMD modes
  i.e. monitor, pause and scale.


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

* The telemetry command ``/eal/heap_info`` is fixed to print ``Heap_id``.

* The experimental function ``rte_pcapng_copy`` was updated to support comment
  section in enhanced packet block in the pcapng library.

* The experimental structures ``struct rte_graph_param``, ``struct rte_graph``
  and ``struct graph`` were updated to support pcap trace in the graph library.


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

* No ABI change that would break compatibility with 22.11.


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

* Intel\ |reg| platforms with NVIDIA\ |reg| NICs combinations

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

    * Red Hat Enterprise Linux release 9.1 (Plow)
    * Red Hat Enterprise Linux release 8.6 (Ootpa)
    * Red Hat Enterprise Linux release 8.4 (Ootpa)
    * Red Hat Enterprise Linux Server release 7.9 (Maipo)
    * Red Hat Enterprise Linux Server release 7.6 (Maipo)
    * Ubuntu 22.04
    * Ubuntu 20.04
    * SUSE Enterprise Linux 15 SP2

  * OFED:

    * MLNX_OFED 5.9-0.5.6.0 and above

  * upstream kernel:

    * Linux 6.3.0-rc3 and above

  * rdma-core:

    * rdma-core-45.0 and above

  * NICs:

    * NVIDIA\ |reg| ConnectX\ |reg|-3 Pro 40G MCX354A-FCC_Ax (2x40G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1007
      * Firmware version: 2.42.5000

    * NVIDIA\ |reg| ConnectX\ |reg|-3 Pro 40G MCX354A-FCCT (2x40G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1007
      * Firmware version: 2.42.5000

    * NVIDIA\ |reg| ConnectX\ |reg|-4 Lx 25G MCX4121A-ACAT (2x25G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1015
      * Firmware version: 14.32.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-4 Lx 50G MCX4131A-GCAT (1x50G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1015
      * Firmware version: 14.32.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 100G MCX516A-CCAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.36.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 100G MCX556A-ECAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.36.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 100G MCX556A-EDAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.36.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 Ex EN 100G MCX516A-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:1019
      * Firmware version: 16.36.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-6 Dx EN 100G MCX623106AN-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:101d
      * Firmware version: 22.36.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-6 Lx EN 25G MCX631102AN-ADAT (2x25G)

      * Host interface: PCI Express 4.0 x8
      * Device ID: 15b3:101f
      * Firmware version: 26.36.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-7 200G CX713106AE-HEA_QP1_Ax (2x200G)

      * Host interface: PCI Express 5.0 x16
      * Device ID: 15b3:1021
      * Firmware version: 28.36.1010 and above

* NVIDIA\ |reg| BlueField\ |reg| SmartNIC

  * NVIDIA\ |reg| BlueField\ |reg|-2 SmartNIC MT41686 - MBF2H332A-AEEOT_A1 (2x25G)

    * Host interface: PCI Express 3.0 x16
    * Device ID: 15b3:a2d6
    * Firmware version: 24.35.2000 and above

  * Embedded software:

    * Ubuntu 20.04.3
    * MLNX_OFED 5.8-1.0.1.1 and above
    * DOCA 1.5.1 with BlueField 3.9.3
    * DPDK application running on ARM cores

* IBM Power 9 platforms with NVIDIA\ |reg| NICs combinations

  * CPU:

    * POWER9 2.2 (pvr 004e 1202)

  * OS:

    * Ubuntu 20.04

  * NICs:

    * NVIDIA\ |reg| ConnectX\ |reg|-5 100G MCX556A-ECAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.36.1010

    * NVIDIA\ |reg| ConnectX\ |reg|-6 Dx 100G MCX623106AN-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:101d
      * Firmware version: 22.36.1010

  * OFED:

    * MLNX_OFED 5.9-0.5.6.0
