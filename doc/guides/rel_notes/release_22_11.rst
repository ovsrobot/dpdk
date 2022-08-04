.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2022 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 22.11
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_22_11.html


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

* ethdev: Removed deprecated ``ETH_LINK_SPEED_*``, ``ETH_SPEED_NUM_*`` and
  ``ETH_LINK_*`` (duplex-related) defines. Use corresponding defines
  with ``RTE_`` prefix instead.

* ethdev: Removed deprecated ``ETH_MQ_RX_*`` and ``ETH_MQ_TX_*`` defines.
  Use corresponding defines with ``RTE_`` prefix instead.

* ethdev: Removed deprecated ``ETH_RSS_*`` defines for hash function and
  RETA size specification. Use corresponding defines with ``RTE_`` prefix
  instead.

* ethdev: Removed deprecated ``DEV_RX_OFFLOAD_*`` and ``DEV_TX_OFFLOAD_``
  defines. Use corresponding defines with ``RTE_ETH_RX_OFFLOAD_`` and
  ``RTE_ETH_TX_OFFLOAD_`` prefix instead.

* ethdev: Removed deprecated ``ETH_DCB_*``, ``ETH_VMDQ_``, ``ETH_*_TCS``,
  ``ETH_*_POOLS`` and ``ETH_MAX_VMDQ_POOL`` defines. Use corresponding
  defines with ``RTE_`` prefix instead.

* ethdev: Removed deprecated ``RTE_TUNNEL_*`` defines. Use corresponding
  defines with ``RTE_ETH_TUNNEL_`` prefix instead.

* ethdev: Removed deprecated ``RTE_FC_*`` defines. Use corresponding
  defines with ``RTE_ETH_FC_`` prefix instead.

* ethdev: Removed deprecated ``ETH_VLAN_*`` and ``ETH_QINQ_`` defines.
  Use corresponding defines with ``RTE_`` prefix instead.


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
