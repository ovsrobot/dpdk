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

Enable / Disable
   ``rte_eth_timesync_enable(port_id)`` enables hardware timestamping on the specified port.
   ``rte_eth_timesync_disable(port_id)`` disables timesync offloads.
   The application must ensure no Tx timestamp operations are in flight before disabling timesync, unless the PMD explicitly supports concurrent disable and Tx timestamp operations.
   This does not make the PMD hardware lifecycle safe by itself.

Clock Time Read / Write
   ``rte_eth_timesync_read_time(port_id, &ts)`` reads the current PHC wall-clock time as a ``struct timespec``.
   ``rte_eth_timesync_write_time(port_id, &ts)`` sets the PHC wall-clock time.

Clock Adjustments
   ``rte_eth_timesync_adjust_time(port_id, delta_ns)`` adjusts the clock phase by a delta offset in nanoseconds.
   ``rte_eth_timesync_adjust_freq(port_id, scaled_ppm)`` adjusts the clock frequency in scaled parts-per-million (1 ppm = 1 << 16).


Receive (Rx) Timestamping
-------------------------

When receive timestamping is enabled, the hardware identifies incoming PTP packets and latches their arrival time.

Rx Timestamp Extraction Workflow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. On packet reception via ``rte_eth_rx_burst()``, the PMD checks if the received mbuf represents a PTP packet.
2. The PMD sets the ``RTE_MBUF_F_RX_IEEE1588_PTP`` flag in ``mbuf->ol_flags``.
3. Depending on the PMD and hardware capability, the Rx timestamp is either:

   Extracted via API
      Application calls ``rte_eth_timesync_read_rx_timestamp(port_id, &ts, flags)``.

   Inlined in Mbuf
      Stored in a registered mbuf dynamic field (e.g. ``rte_mbuf_dyn_rx_timestamp_register()``).


PMD Implementation Requirements
-------------------------------

To support full timesync capabilities, a Poll Mode Driver (PMD) implements the following driver contract:

1. Clock Operations
   (``timesync_enable``, ``timesync_disable``, ``timesync_read_time``, ``timesync_write_time``, ``timesync_adjust_time``, ``timesync_adjust_freq``)

   Controls hardware timestamp generation and disciplines the hardware clock registers.

2. Rx Timestamping (``timesync_read_rx_timestamp``)

   Configures Rx filters to latch incoming PTP arrival times and flags received mbufs with ``RTE_MBUF_F_RX_IEEE1588_PTP``.
