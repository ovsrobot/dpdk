.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2026 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 26.07
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_26_07.html


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

* **Added option to disable auto probing.**

  Added EAL options affecting the initial bus probing.

  * ``-A`` or ``--no-auto-probing`` disable the initial bus probing: no device is probed during
    ``rte_eal_init`` and the application is responsible for probing each device,
  * ``--auto-probing`` enables the initial bus probing, which is the current default behavior.

* **Added LinkData sxe2 ethernet driver.**

  Added network driver for the LinkData network adapters.

* **Updated Intel iavf driver.**

  * Added support for transmitting LLDP packets based on mbuf packet type.
  * Implemented AVX2 context descriptor transmit paths.

* **Updated PCAP ethernet driver.**

  * Added support for VLAN insertion and stripping.
  * Added support for reporting link state in ``iface`` mode.
  * Added support for link state interrupt in ``iface`` mode.
  * Added nanosecond precision to timestamp support.
  * Added ``snaplen`` devarg to configure packet capture snapshot length.
  * Added ``eof`` devarg to use link state to signal end of receive file input.
  * Added unit test suite.


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

* **ethdev: promoted several APIs from experimental to stable.**

  The following ethdev APIs are no longer marked experimental:

  * ``rte_eth_buffer_split_get_supported_hdr_ptypes``
  * ``rte_eth_cman_config_get``
  * ``rte_eth_cman_config_init``
  * ``rte_eth_cman_config_set``
  * ``rte_eth_cman_info_get``
  * ``rte_eth_dev_capability_name``
  * ``rte_eth_dev_conf_get``
  * ``rte_eth_dev_count_aggr_ports``
  * ``rte_eth_dev_get_module_eeprom``
  * ``rte_eth_dev_get_module_info``
  * ``rte_eth_dev_get_reg_info_ext``
  * ``rte_eth_dev_hairpin_capability_get``
  * ``rte_eth_dev_map_aggr_tx_affinity``
  * ``rte_eth_dev_priority_flow_ctrl_queue_configure``
  * ``rte_eth_dev_priority_flow_ctrl_queue_info_get``
  * ``rte_eth_dev_priv_dump``
  * ``rte_eth_dev_rss_algo_name``
  * ``rte_eth_fec_get``
  * ``rte_eth_fec_get_capability``
  * ``rte_eth_fec_set``
  * ``rte_eth_find_rss_algo``
  * ``rte_eth_get_monitor_addr``
  * ``rte_eth_hairpin_bind``
  * ``rte_eth_hairpin_get_peer_ports``
  * ``rte_eth_hairpin_unbind``
  * ``rte_eth_ip_reassembly_capability_get``
  * ``rte_eth_ip_reassembly_conf_get``
  * ``rte_eth_ip_reassembly_conf_set``
  * ``rte_eth_link_speed_to_str``
  * ``rte_eth_link_to_str``
  * ``rte_eth_macaddrs_get``
  * ``rte_eth_read_clock``
  * ``rte_eth_recycle_mbufs``
  * ``rte_eth_recycle_rx_queue_info_get``
  * ``rte_eth_representor_info_get``
  * ``rte_eth_rx_avail_thresh_query``
  * ``rte_eth_rx_avail_thresh_set``
  * ``rte_eth_rx_descriptor_dump``
  * ``rte_eth_rx_hairpin_queue_setup``
  * ``rte_eth_rx_queue_is_valid``
  * ``rte_eth_speed_lanes_get``
  * ``rte_eth_speed_lanes_get_capability``
  * ``rte_eth_speed_lanes_set``
  * ``rte_eth_timesync_adjust_freq``
  * ``rte_eth_tx_descriptor_dump``
  * ``rte_eth_tx_hairpin_queue_setup``
  * ``rte_eth_tx_queue_count``
  * ``rte_eth_tx_queue_is_valid``
  * ``rte_eth_xstats_query_state``
  * ``rte_eth_xstats_set_counter``


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

* No ABI change that would break compatibility with 25.11.


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
