.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2026 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 26.11
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_26_11.html


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

* Removed deprecated symbols:

  * eal: ``__rte_packed``
  * fib: ``RTE_FIB6_IPV6_ADDR_SIZE``, ``RTE_FIB6_MAXDEPTH``
  * lpm: ``RTE_LPM6_IPV6_ADDR_SIZE``, ``RTE_LPM6_MAX_DEPTH``
  * net: ``RTE_IP_ICMP_ECHO_REPLY``, ``RTE_IP_ICMP_ECHO_REQUEST``
  * pci: ``PCI_ID_ANY``
  * rib: ``RTE_RIB6_IPV6_ADDR_SIZE``, ``get_msk_part``, ``rte_rib6_copy_addr``,
    ``rte_rib6_is_equal``
  * table: ``RTE_LPM_IPV6_ADDR_SIZE``


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

* eventdev: Promoted the following API from experimental to stable:

  * Rx adapter: ``rte_event_eth_rx_adapter_create_ext_with_params``,
    ``rte_event_eth_rx_adapter_runtime_params_init``,
    ``rte_event_eth_rx_adapter_runtime_params_set`` and
    ``rte_event_eth_rx_adapter_runtime_params_get``
  * Tx adapter: ``rte_event_eth_tx_adapter_runtime_params_init``,
    ``rte_event_eth_tx_adapter_runtime_params_set`` and
    ``rte_event_eth_tx_adapter_runtime_params_get``
  * crypto adapter: ``rte_event_crypto_adapter_runtime_params_init``,
    ``rte_event_crypto_adapter_runtime_params_set`` and
    ``rte_event_crypto_adapter_runtime_params_get``
  * timer adapter: ``rte_event_timer_remaining_ticks_get``
  * DMA adapter: ``rte_event_dma_adapter_*``
  * link profiles: ``rte_event_port_profile_links_set``,
    ``rte_event_port_profile_links_get`` and
    ``rte_event_port_profile_unlink``

* reorder: Promoted the following API from experimental to stable:
  ``rte_reorder_seqn``, ``rte_reorder_drain_up_to_seqn``,
  ``rte_reorder_min_seqn_set`` and ``rte_reorder_memory_footprint_get``.

* telemetry: Promoted the following API from experimental to stable:

  * ``rte_tel_data_add_array_uint_hex``
  * ``rte_tel_data_add_dict_uint_hex``
  * ``rte_telemetry_register_cmd_arg``

* rib: The node mempool created by ``rte_rib_create()`` and ``rte_rib6_create()``
  is now named ``RIB_<name>`` and ``RIB6_<name>`` instead of ``MP_<name>``.

* fib: The RIB created by ``rte_fib_create()`` and ``rte_fib6_create()``
  is now named ``FIB_<name>`` and ``FIB6_<name>``.

* rib, fib: The name of a RIB, RIB6, FIB or FIB6 is used to derive the name of
  its node mempool, which is bounded by ``RTE_MEMPOOL_NAMESIZE``.
  As the prefixes above are added on top of the name,
  the maximum length of a name is the following:

  * RIB  - 53 characters.
  * RIB6 - 52 characters.
  * FIB  - 49 characters.
  * FIB6 - 47 characters.

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

* **Increased memzone maximum name size.**

  ``RTE_MEMZONE_NAMESIZE`` was increased from 32 to 64,
  and the derived ``RTE_RING_NAMESIZE``, ``RTE_MEMPOOL_NAMESIZE``,
  ``RTE_STACK_NAMESIZE`` and ``RTE_RCU_QSBR_DQ_NAMESIZE`` grew accordingly.
  This impacts the following structures:

  * ``struct rte_memzone`` grew by 32 bytes.

  * ``struct rte_ring`` grew by one cache line,
    and ``memzone`` and ``name`` were moved after the size fields
    to keep the datapath fields in the first cache line.

  * ``struct rte_mempool`` is unchanged in size,
    but the fields were reordered so the datapath fields
    (``pool_data``/``pool_id``, ``local_cache``, ``ops_index``
    and ``cache_size``) come first,
    and ``name``, ``pool_config`` and ``mz`` were moved after them.

  * ``struct rte_stack`` grew by one cache line.


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
