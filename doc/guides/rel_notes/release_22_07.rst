.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2022 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 22.07
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_22_07.html


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

* **Added vhost API to get the number of in-flight packets.**

  Added an API which can get the number of in-flight packets in
  vhost async data path without using lock.

* **Updated Intel iavf driver.**

  * Added Tx QoS queue rate limitation support.
  * Added quanta size configuration support.
  * Added ``DEV_RX_OFFLOAD_TIMESTAMP`` support.

* **Updated Intel ice driver.**

 * Added support for RSS RETA configure in DCF mode.
 * Added support for RSS HASH configure in DCF mode.
 * Added support for MTU configure in DCF mode.
 * Added support for promisc configuration in DCF mode.
 * Added support for MAC configuration in DCF mode.
 * Added support for VLAN filter and offload configuration in DCF mode.

* **Updated Mellanox mlx5 driver.**

  * Added support for promiscuous mode on Windows.
  * Added support for MTU on Windows.
  * Added matching and RSS on IPsec ESP.

* **Updated Marvell cnxk crypto driver.**

  * Added AH mode support in lookaside protocol (IPsec) for CN9K & CN10K.
  * Added AES-GMAC support in lookaside protocol (IPsec) for CN9K & CN10K.

* **Added eventdev API to quiesce an event port.**

  Added the function ``rte_event_port_quiesce()``
  to quiesce any lcore-specific resources consumed by the event port,
  when the lcore is no more associated with an event port.

* **Added support for setting queue attributes at runtime in eventdev.**

  Added new API ``rte_event_queue_attr_set()``, to set event queue attributes
  at runtime.

* **Added new queues attributes weight and affinity in eventdev.**

  Defined new event queue attributes weight and affinity as below:

  * ``RTE_EVENT_QUEUE_ATTR_WEIGHT``
  * ``RTE_EVENT_QUEUE_ATTR_AFFINITY``


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

* The DPDK header file ``rte_altivec.h``,
  which is a wrapper for the PPC header file ``altivec.h``,
  undefines the AltiVec keyword ``vector``.
  The alternative keyword ``__vector`` should be used instead.


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

* No ABI change that would break compatibility with 21.11.


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
