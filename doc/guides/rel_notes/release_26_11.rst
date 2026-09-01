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

* ethdev: Promoted the following API from experimental to stable:

  * meter (MTR) and policing: ``rte_mtr_*``
  * SFF: ``rte_eth_dev_get_module_info`` and ``rte_eth_dev_get_module_eeprom``
  * flow conversion: ``rte_flow_conv``
  * hairpin queue: ``rte_eth_rx_hairpin_queue_setup``,
    ``rte_eth_tx_hairpin_queue_setup``,
    ``rte_eth_dev_hairpin_capability_get``,
    ``rte_eth_hairpin_bind``,
    ``rte_eth_hairpin_unbind``,
    ``rte_eth_hairpin_get_peer_ports``
  * clock: ``rte_eth_read_clock``
  * flow dump: ``rte_flow_dev_dump``
  * FEC: ``rte_eth_fec_get_capability``, ``rte_eth_fec_get`` and ``rte_eth_fec_set``
  * link speed: ``rte_eth_link_speed_to_str`` and ``rte_eth_link_to_str``
  * flow tunnel: ``rte_flow_tunnel_decap_set``, ``rte_flow_tunnel_match``,
    ``rte_flow_tunnel_item_release``,
    ``rte_flow_tunnel_action_decap_release`` and
    ``rte_flow_get_restore_info``
  * flow age: ``rte_flow_get_aged_flows`` and ``rte_flow_get_q_aged_flows``
  * flow action: ``rte_flow_action_handle_*`` and ``rte_flow_action_list_handle_*``
  * flow template:
    ``rte_flow_configure``, ``rte_flow_info_get``,
    ``rte_flow_pattern_*``,
    ``rte_flow_actions_*``,
    ``rte_flow_template_*``,
    ``rte_flow_async_*``,
    ``rte_flow_push``, ``rte_flow_pull``
  * flow flex: ``rte_flow_flex_item_create`` and ``rte_flow_flex_item_release``
  * remaining flow helpers: ``rte_flow_actions_update``, ``rte_flow_restore_info_dynflag``,
    ``rte_flow_calc_table_hash``, ``rte_flow_group_set_miss_actions``,
    and ``rte_flow_calc_encap_hash``
  * congestion management:
    ``rte_eth_cman_config_init``, ``rte_eth_cman_config_set``,
    ``rte_eth_cman_config_get`` and ``rte_eth_cman_info_get``
  * ip reassembly:
    ``rte_eth_ip_reassembly_capability_get``, ``rte_eth_ip_reassembly_conf_get`` and
    ``rte_eth_ip_reassembly_conf_set``
  * priority flow:
    ``rte_eth_dev_priority_flow_ctrl_queue_configure`` and
    ``rte_eth_dev_priority_flow_ctrl_queue_info_get``
  * device info:
    ``rte_eth_dev_capability_name``, ``rte_eth_dev_conf_get``,
    ``rte_eth_macaddrs_get``, ``rte_eth_dev_priv_dump``,
    ``rte_eth_rx_descriptor_dump``, ``rte_eth_tx_descriptor_dump``,
    ``rte_eth_dev_rss_algo_name``, ``rte_eth_find_rss_algo`` and
    ``rte_eth_dev_get_reg_info_ext``
  * speed lanes:
    ``rte_eth_speed_lanes_get``, ``rte_eth_speed_lanes_set`` and
    ``rte_eth_speed_lanes_get_capability``
  * queue helpers:
    ``rte_eth_rx_queue_is_valid``, ``rte_eth_tx_queue_is_valid``,
    ``rte_eth_rx_avail_thresh_set``, ``rte_eth_rx_avail_thresh_query``,
    ``rte_eth_recycle_rx_queue_info_get``,
    ``rte_eth_dev_count_aggr_ports`` and
    ``rte_eth_dev_map_aggr_tx_affinity``
  * utility funcs:
    ``rte_eth_get_monitor_addr``, ``rte_eth_representor_info_get``,
    ``rte_eth_buffer_split_get_supported_hdr_ptypes``,
    ``rte_eth_timesync_adjust_freq`` and ``rte_tm_node_query``


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
