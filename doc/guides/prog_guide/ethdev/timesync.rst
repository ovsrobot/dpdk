..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Intel Corporation.

IEEE 1588 / PTP Timesync API
============================

Overview
--------

The DPDK IEEE 1588 / Precision Time Protocol (PTP) Timesync API provides
a standardized framework for managing PTP Hardware Clocks (PHCs) and retrieving
precise hardware transmit (Tx) and receive (Rx) timestamps.

The Timesync framework encompasses three core capabilities:

1. **Clock Control & Adjustment**: Enabling/disabling hardware timestamping, reading/setting clock time, and adjusting phase/frequency.
2. **Receive Timestamping**: Hardware capture of incoming PTP packet arrival timestamps.
3. **Transmit Timestamping**: Hardware capture of outbound PTP packet departure timestamps.


Clock Management & Control
--------------------------

To initialize and discipline a port's PTP Hardware Clock (PHC), the API provides:

* **Enable / Disable**:
  ``rte_eth_timesync_enable(port_id)`` enables hardware timestamping on the specified port.
  ``rte_eth_timesync_disable(port_id)`` disables timesync offloads.

* **Clock Time Read / Write**:
  ``rte_eth_timesync_read_time(port_id, &ts)`` reads the current PHC wall-clock time as a ``struct timespec``.
  ``rte_eth_timesync_write_time(port_id, &ts)`` sets the PHC wall-clock time.

* **Clock Adjustments**:
  ``rte_eth_timesync_adjust_time(port_id, delta_ns)`` adjusts the clock phase by a delta offset in nanoseconds.
  ``rte_eth_timesync_adjust_freq(port_id, scaled_ppm)`` adjusts the clock frequency in scaled parts-per-million (1 ppm = 1 << 16).


Receive (Rx) Timestamping
-------------------------

When receive timestamping is enabled, the hardware identifies incoming PTP packets (e.g. IEEE 1588 EtherType ``0x88F7`` or UDP destination ports 319/320) and latches their arrival time.

Rx Timestamp Extraction Workflow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. On packet reception via ``rte_eth_rx_burst()``, the PMD checks if the received mbuf represents a PTP packet.
2. The PMD sets the ``RTE_MBUF_F_RX_IEEE1588_PTP`` flag in ``mbuf->ol_flags``.
3. Depending on the PMD and hardware capability, the Rx timestamp is either:
   * **Extracted via API**: Application calls ``rte_eth_timesync_read_rx_timestamp(port_id, &ts, flags)``.
   * **Inlined in Mbuf**: Stored in a registered mbuf dynamic field (e.g. ``rte_mbuf_dyn_rx_timestamp_register()``).


Transmit (Tx) Timestamping Architectures
----------------------------------------

The framework supports two hardware transmit timestamping architectures:

* **Single Shared Register** (``RTE_ETH_TIMESYNC_TX_TS_SINGLE_REG``):
  The hardware contains a single shared transmit timestamp latch register.
  Only one outbound packet can be timestamped at a time across the entire port.
  The application calls ``rte_eth_timesync_read_tx_timestamp(port_id, &ts)`` to retrieve the departure time.

* **Per-Packet Slot Bank** (``RTE_ETH_TIMESYNC_TX_TS_PER_PACKET``):
  The hardware provides a bank of independent transmit timestamp slots or
  descriptors. Multiple outbound PTP packets can be timestamped concurrently and
  correlated asynchronously on a per-packet basis using slot handles.


Dual-Domain Timestamps
~~~~~~~~~~~~~~~~~~~~~~

When retrieving transmit timestamps using slot handles, the API returns
a dual-domain timestamp structure:

.. code-block:: c

    struct rte_eth_timesync_dual_domain_timestamp {
        int64_t adjusted_ns; /**< PHC adjusted time (wall-clock nanoseconds) */
        int64_t raw_ns;      /**< Free-running hardware cycle counter or raw nanoseconds */
        uint32_t valid_mask; /**< Validity bits for the adjusted/raw domains */
    };

* **Adjusted Domain** (``RTE_ETH_TIMESYNC_DUAL_DOMAIN_TIMESTAMP_ADJUSTED_VALID``):
  Represents the wall-clock time after frequency adjustments (``rte_eth_timesync_adjust_freq``)
  or phase steps (``rte_eth_timesync_adjust_time``) have been applied.

* **Raw Domain** (``RTE_ETH_TIMESYNC_DUAL_DOMAIN_TIMESTAMP_RAW_VALID``):
  Represents the unadjusted free-running hardware cycle counter or raw timestamp.
  This domain is required when correlating adjusted wall-clock time with the
  underlying hardware timebase or when performing cross-timestamp analysis.


Per-Packet Tx Timestamp Workflow
--------------------------------

To use per-packet transmit timestamping, applications follow this sequence:

1. **Query Port Capabilities**
   Determine whether the PMD supports slot-based per-packet timestamping:

   .. code-block:: c

       struct rte_eth_timesync_tx_ts_caps caps;

       ret = rte_eth_timesync_tx_timestamp_slot_get_capabilities(port_id, &caps);
       if (ret == 0 && caps.type == RTE_ETH_TIMESYNC_TX_TS_PER_PACKET) {
           printf("Port %u supports per-packet timestamping with %u max slots\n",
                  port_id, caps.max_slots);
       }

2. **Register Mbuf Dynamic Fields**
   Register the dynamic field and dynamic flag used to pass slot handles to the Tx datapath:

   .. code-block:: c

       ret = rte_eth_timesync_tx_slot_dynfield_register();
       if (ret < 0) {
           /* Dynamic field space exhausted or registration failed */
       }

   .. note::

      ``rte_eth_timesync_enable()`` registers the dynamic field automatically.
      Call ``rte_eth_timesync_tx_slot_dynfield_register()`` explicitly only if creating
      mempools before enabling timesync on the port.

3. **Allocate a Timestamp Slot**
   Before transmitting a PTP packet requiring a transmit timestamp, allocate a slot handle:

   .. code-block:: c

       uint32_t slot_id;

       ret = rte_eth_timesync_tx_timestamp_slot_alloc(port_id, &slot_id);
       if (ret != 0) {
           /* Handle allocation error (e.g. -ENOSPC if all slots are in flight) */
       }

4. **Stamp the Mbuf**
   Attach the allocated slot handle to the mbuf:

   .. code-block:: c

       rte_eth_timesync_tx_timestamp_stamp_mbuf(port_id, slot_id, mbuf);
       mbuf->ol_flags |= RTE_MBUF_F_TX_IEEE1588_TMST;

5. **Transmit the Packet**
   Send the packet via ``rte_eth_tx_burst()`` as usual.

6. **Poll for Timestamp Completion**
   Read the captured timestamp using the allocated slot handle:

   .. code-block:: c

       struct rte_eth_timesync_dual_domain_timestamp ts;

       ret = rte_eth_timesync_read_tx_timestamp_slot(port_id, slot_id, &ts);
       if (ret == 0) {
           /* Timestamp is ready */
           if (ts.valid_mask & RTE_ETH_TIMESYNC_DUAL_DOMAIN_TIMESTAMP_ADJUSTED_VALID) {
               /* Process ts.adjusted_ns */
           }
       } else if (ret == -EAGAIN) {
           /* Timestamp hardware processing is still pending; retry later */
       }

7. **Release the Slot**
   After successfully reading the timestamp or timing out, release the slot handle:

   .. code-block:: c

       rte_eth_timesync_tx_timestamp_slot_release(port_id, slot_id);

8. **Unregister Dynfield State on Shutdown (Optional)**
   When shutting down timesync offloads, the application can unregister the cached dynfield state:

   .. code-block:: c

       rte_eth_timesync_tx_slot_dynfield_unregister();

   .. note::

      This resets process-local dynfield state so subsequent
      ``rte_eth_timesync_tx_timestamp_stamp_mbuf()`` calls return ``-ENOTSUP``
      and PMD Tx datapaths fall back to port-level legacy mode.
      Note that underlying mbuf dynfield bytes remain allocated in DPDK layout as DPDK does not
      support dynamic field deallocation.


PMD Implementation Requirements
-------------------------------

To support full timesync capabilities, a Poll Mode Driver (PMD) implements the following driver contract:

1. **Clock Operations** (``timesync_enable``, ``timesync_disable``, ``timesync_read_time``, ``timesync_write_time``, ``timesync_adjust_time``, ``timesync_adjust_freq``)
   * Controls hardware timestamp generation and disciplines the hardware clock registers.

2. **Rx Timestamping** (``timesync_read_rx_timestamp``)
   * Configures Rx filters to latch incoming PTP arrival times and flags received mbufs with ``RTE_MBUF_F_RX_IEEE1588_PTP``.

3. **Tx Slot Capability Reporting** (``timesync_tx_ts_get_capabilities``)
   * Reports ``RTE_ETH_TIMESYNC_TX_TS_SINGLE_REG`` or ``RTE_ETH_TIMESYNC_TX_TS_PER_PACKET`` in `caps->type` and sets `caps->max_slots`.

4. **Slot Allocation & Release** (``timesync_tx_timestamp_slot_alloc`` / ``timesync_tx_timestamp_slot_release``)
   * Maintains a port-global pool or bitmap of hardware timestamp slots.
   * `timesync_tx_timestamp_slot_alloc` returns a port-unique slot identifier and returns ``-ENOSPC`` when no slots are free.
   * `timesync_tx_timestamp_slot_release` clears hardware slot state and returns the slot handle to the free pool.

5. **Tx Datapath Integration**
   * Checks if ``RTE_MBUF_F_TX_IEEE1588_TMST`` is set on `mbuf->ol_flags`.
   * For per-packet slot mode, retrieves `slot_id` from mbuf dynamic field via ``*RTE_MBUF_DYNFIELD(m, dynfield_offset, uint32_t *)``.
   * Configures hardware Tx descriptors to capture departure timestamps into the specified slot.

6. **Tx Slot Timestamp Retrieval** (``timesync_read_tx_timestamp_slot``)
   * Queries hardware slot or descriptor completion ring corresponding to `slot_id`.
   * Populates ``struct rte_eth_timesync_dual_domain_timestamp`` and returns ``0`` when ready, or ``-EAGAIN`` if pending.
