.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2023 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 24.03
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_24_03.html


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

* gso: ``rte_gso_segment`` now returns -ENOTSUP for unknown protocols.

* ethdev: PMDs implementing asynchronous flow operations are required to provide relevant functions
  implementation through ``rte_flow_fp_ops`` struct, instead of ``rte_flow_ops`` struct.
  Pointer to device-dependent ``rte_flow_fp_ops`` should be provided to ``rte_eth_dev.flow_fp_ops``.
  This change applies to the following API functions:

   * ``rte_flow_async_create``
   * ``rte_flow_async_create_by_index``
   * ``rte_flow_async_actions_update``
   * ``rte_flow_async_destroy``
   * ``rte_flow_push``
   * ``rte_flow_pull``
   * ``rte_flow_async_action_handle_create``
   * ``rte_flow_async_action_handle_destroy``
   * ``rte_flow_async_action_handle_update``
   * ``rte_flow_async_action_handle_query``
   * ``rte_flow_async_action_handle_query_update``
   * ``rte_flow_async_action_list_handle_create``
   * ``rte_flow_async_action_list_handle_destroy``
   * ``rte_flow_async_action_list_handle_query_update``

* ethdev: Removed the following fields from ``rte_flow_ops`` struct:

   * ``async_create``
   * ``async_create_by_index``
   * ``async_actions_update``
   * ``async_destroy``
   * ``push``
   * ``pull``
   * ``async_action_handle_create``
   * ``async_action_handle_destroy``
   * ``async_action_handle_update``
   * ``async_action_handle_query``
   * ``async_action_handle_query_update``
   * ``async_action_list_handle_create``
   * ``async_action_list_handle_destroy``
   * ``async_action_list_handle_query_update``


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

* No ABI change that would break compatibility with 23.11.


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
