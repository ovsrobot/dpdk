.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2023 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 23.11
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_23_11.html

* Build Requirements: From DPDK 23.11 onwards,
  building DPDK will require a C compiler which supports the C11 standard,
  including support for C11 standard atomics.

  More specifically, the requirements will be:

  * Support for flag "-std=c11" (or similar)
  * __STDC_NO_ATOMICS__ is *not defined* when using c11 flag

  Please note:

  * C11, including standard atomics, is supported from GCC version 5 onwards,
    and is the default language version in that release
    (Ref: https://gcc.gnu.org/gcc-5/changes.html)
  * C11 is the default compilation mode in Clang from version 3.6,
    which also added support for standard atomics
    (Ref: https://releases.llvm.org/3.6.0/tools/clang/docs/ReleaseNotes.html)

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

* **Added mbuf recycling support.**

  Added ``rte_eth_recycle_rx_queue_info_get`` and ``rte_eth_recycle_mbufs``
  functions which allow the user to copy used mbufs from the Tx mbuf ring
  into the Rx mbuf ring. This feature supports the case that the Rx Ethernet
  device is different from the Tx Ethernet device with respective driver
  callback functions in ``rte_eth_recycle_mbufs``.

* **Added amd-pstate driver support to power management library.**

  Added support for amd-pstate driver which works on AMD EPYC processors.

* **Updated Solarflare net driver.**

  * Added support for transfer flow action ``INDIRECT`` with subtype ``VXLAN_ENCAP``.

* build: Enabling deprecated libraries is now done using the new
  ``enable_deprecated_libraries`` build option.

* build: Optional libraries can now be selected with the new ``enable_libs``
  build option similarly to the existing ``enable_drivers`` build option.

* eal: Introduced a new API for atomic operations. This new API serves as a
  wrapper for transitioning to standard atomic operations as described in the
  C11 standard. This API implementation points at the compiler intrinsics by
  default. The implementation using C11 standard atomic operations is enabled
  via the ``enable_stdatomic`` build option.


Removed Items
-------------

.. This section should contain removed items in this release. Sample format:

   * Add a short 1-2 sentence description of the removed item
     in the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* eal: Removed deprecated ``RTE_FUNC_PTR_OR_*`` macros.

* ethdev: Removed deprecated macro ``RTE_ETH_DEV_BONDED_SLAVE``.

* flow_classify: Removed flow classification library and examples.

* kni: Removed the Kernel Network Interface (KNI) library and driver.


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

* eal: The thread API has changed.
  The function ``rte_thread_create_control()`` does not take attributes anymore.
  The whole thread API was promoted to stable level,
  except ``rte_thread_setname()`` and ``rte_ctrl_thread_create()`` which are
  replaced with ``rte_thread_set_name()`` and ``rte_thread_create_control()``.

* eal: Removed ``RTE_CPUFLAG_NUMFLAGS`` to avoid misusage and theoretical ABI
  compatibility issue when adding new cpuflags.

* bonding: Replaced master/slave to main/member. The data structure
  ``struct rte_eth_bond_8023ad_slave_info`` was renamed to
  ``struct rte_eth_bond_8023ad_member_info`` in DPDK 23.11.
  The following functions were removed in DPDK 23.11.
  The old functions:
  ``rte_eth_bond_8023ad_slave_info``,
  ``rte_eth_bond_active_slaves_get``,
  ``rte_eth_bond_slave_add``,
  ``rte_eth_bond_slave_remove``, and
  ``rte_eth_bond_slaves_get``
  will be replaced by:
  ``rte_eth_bond_8023ad_member_info``,
  ``rte_eth_bond_active_members_get``,
  ``rte_eth_bond_member_add``,
  ``rte_eth_bond_member_remove``, and
  ``rte_eth_bond_members_get``.


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

* ethdev: Added ``recycle_tx_mbufs_reuse`` and ``recycle_rx_descriptors_refill``
  fields to ``rte_eth_dev`` structure.

* ethdev: Structure ``rte_eth_fp_ops`` was affected to add
  ``recycle_tx_mbufs_reuse`` and ``recycle_rx_descriptors_refill``
  fields, to move ``rxq`` and ``txq`` fields, to change the size of
  ``reserved1`` and ``reserved2`` fields.


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
