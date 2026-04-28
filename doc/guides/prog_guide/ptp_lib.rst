..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Intel Corporation.

PTP Protocol Library
====================

The DPDK PTP library provides IEEE 1588 / Precision Time Protocol (PTP)
packet structures, constants, and helper functions for PTP packet processing.

The library supports classification and header parsing of PTP messages
across multiple transport encapsulations:

- L2 PTP (EtherType 0x88F7)
- VLAN-tagged L2 PTP (single or double VLAN, TPIDs 0x8100 and 0x88A8)
- PTP over UDP/IPv4 (destination ports 319 and 320)
- PTP over UDP/IPv6 (destination ports 319 and 320)
- VLAN-tagged PTP over UDP/IPv4 or UDP/IPv6

The library conforms to
`IEEE 1588-2019 <https://standards.ieee.org/ieee/1588/6825/>`_
(Precision Time Protocol).

Overview
--------

PTP is the foundation of time synchronization in networking.
DPDK applications that relay, classify, or timestamp PTP packets
currently duplicate header definitions and parsing logic.
This library provides a shared, tested implementation.

The library provides:

#. Packed header structures matching the IEEE 1588-2019 wire format
#. Constants for message types, flags, ports, and multicast addresses
#. Inline helpers for common field extraction and manipulation
#. Packet classification across L2, VLAN, UDP/IPv4, and UDP/IPv6 transports
#. Correction field manipulation for Transparent Clock residence time

PTP Message Types
-----------------

IEEE 1588-2019 defines the following message types, all supported by the library:

.. csv-table:: PTP Message Types
   :header: "Type", "Name", "Category", "Macro"
   :widths: 5, 20, 10, 30

   "0x0", "Sync", "Event", "``RTE_PTP_MSGTYPE_SYNC``"
   "0x1", "Delay_Req", "Event", "``RTE_PTP_MSGTYPE_DELAY_REQ``"
   "0x2", "Peer_Delay_Req", "Event", "``RTE_PTP_MSGTYPE_PDELAY_REQ``"
   "0x3", "Peer_Delay_Resp", "Event", "``RTE_PTP_MSGTYPE_PDELAY_RESP``"
   "0x8", "Follow_Up", "General", "``RTE_PTP_MSGTYPE_FOLLOW_UP``"
   "0x9", "Delay_Resp", "General", "``RTE_PTP_MSGTYPE_DELAY_RESP``"
   "0xA", "PDelay_Resp_Follow_Up", "General", "``RTE_PTP_MSGTYPE_PDELAY_RESP_FU``"
   "0xB", "Announce", "General", "``RTE_PTP_MSGTYPE_ANNOUNCE``"
   "0xC", "Signaling", "General", "``RTE_PTP_MSGTYPE_SIGNALING``"
   "0xD", "Management", "General", "``RTE_PTP_MSGTYPE_MANAGEMENT``"

Event messages (types 0x0–0x3) require hardware timestamps for accurate
time transfer.

Header Structures
-----------------

The library defines the following packed structures that map directly to
the IEEE 1588-2019 wire format:

``struct rte_ptp_hdr``
   Common PTP message header (34 bytes). All PTP messages begin with this header.
   Contains message type, version, flags, correction field, source port identity,
   sequence ID, and log message interval.

``struct rte_ptp_timestamp``
   PTP timestamp (10 bytes). Used in Sync, Delay_Req, and Follow_Up message bodies.
   Contains seconds (48-bit) and nanoseconds (32-bit).

``struct rte_ptp_port_id``
   PTP port identity (10 bytes). Contains an EUI-64 clock identity and a
   16-bit port number.

Packet Classification API
--------------------------

``rte_ptp_classify()``
~~~~~~~~~~~~~~~~~~~~~~

Classify a packet and return the PTP message type.

.. code-block:: C

   int rte_ptp_classify(const struct rte_mbuf *m);

Examines the mbuf to determine if it contains a PTP message.
Returns the PTP message type (0x0–0xF) on success,
or ``RTE_PTP_MSGTYPE_INVALID`` (-1) if the packet is not PTP.

Supported encapsulations (VLAN TPIDs recognised: 0x8100 and 0x88A8):

- EtherType 0x88F7 (L2 PTP)
- Single VLAN (0x8100 or 0x88A8) + EtherType 0x88F7
- Double VLAN (any combination of 0x8100 / 0x88A8) + EtherType 0x88F7
- IPv4 + UDP destination port 319 or 320
- IPv6 + UDP destination port 319 or 320
- Single or double VLAN + IPv4/IPv6 + UDP destination port 319 or 320

``rte_ptp_hdr_get()``
~~~~~~~~~~~~~~~~~~~~~

Get a pointer to the PTP header inside a packet.

.. code-block:: C

   struct rte_ptp_hdr *rte_ptp_hdr_get(const struct rte_mbuf *m);

Returns a pointer to the PTP header, or NULL if the packet is not PTP.
Handles the same set of encapsulations as ``rte_ptp_classify()``.

``rte_ptp_msg_type_str()``
~~~~~~~~~~~~~~~~~~~~~~~~~~

Convert a PTP message type to a human-readable string.

.. code-block:: C

   const char *rte_ptp_msg_type_str(int msg_type);

Returns a string such as ``"Sync"``, ``"Delay_Req"``, ``"Follow_Up"``, etc.
Returns ``"Not_PTP"`` for invalid message types.

Inline Helpers
--------------

The following inline functions operate on ``struct rte_ptp_hdr`` and require
no function call overhead:

.. csv-table:: Inline Helper Functions
   :header: "Function", "Returns", "Description"
   :widths: 30, 15, 40

   "``rte_ptp_msg_type()``", "``uint8_t``", "Extract message type (lower nibble)"
   "``rte_ptp_transport_specific()``", "``uint8_t``", "Extract transport-specific field (upper nibble)"
   "``rte_ptp_version()``", "``uint8_t``", "Extract PTP version number"
   "``rte_ptp_seq_id()``", "``uint16_t``", "Get sequence ID in host byte order"
   "``rte_ptp_domain()``", "``uint8_t``", "Get PTP domain number"
   "``rte_ptp_is_event()``", "``bool``", "Check if message type is an event (0x0–0x3)"
   "``rte_ptp_is_two_step()``", "``bool``", "Check if two-step flag is set"
   "``rte_ptp_correction_ns()``", "``int64_t``", "Get correctionField in nanoseconds (from 48.16 fixed-point)"
   "``rte_ptp_add_correction()``", "``void``", "Add residence time to correctionField (for Transparent Clocks)"
   "``rte_ptp_timestamp_to_ns()``", "``uint64_t``", "Convert PTP timestamp struct to nanoseconds"

Usage Example
-------------

Classifying and processing PTP packets:

.. code-block:: C

   #include <rte_ptp.h>

   void process_packets(struct rte_mbuf **pkts, uint16_t nb_pkts)
   {
       for (uint16_t i = 0; i < nb_pkts; i++) {
           int ptp_type = rte_ptp_classify(pkts[i]);
           if (ptp_type == RTE_PTP_MSGTYPE_INVALID)
               continue;

           struct rte_ptp_hdr *hdr = rte_ptp_hdr_get(pkts[i]);

           printf("PTP %s seq=%u domain=%u\n",
                  rte_ptp_msg_type_str(ptp_type),
                  rte_ptp_seq_id(hdr),
                  rte_ptp_domain(hdr));

           if (rte_ptp_is_event(ptp_type)) {
               /* Event message — needs hardware timestamp */
           }
       }
   }

.. note::

   ``rte_ptp_classify()`` and ``rte_ptp_hdr_get()`` both parse the packet
   internally.  When the caller needs both the message type and a header
   pointer, calling ``rte_ptp_hdr_get()`` alone and then using
   ``rte_ptp_msg_type()`` on the returned header avoids parsing the
   packet twice.

Adding residence time for a Transparent Clock:

.. code-block:: C

   struct rte_ptp_hdr *hdr = rte_ptp_hdr_get(pkt);
   if (hdr != NULL) {
       int64_t residence_ns = egress_ts - ingress_ts;
       rte_ptp_add_correction(hdr, residence_ns);
   }

Limitations
-----------

- IPv6 extension headers are not traversed. Only the base IPv6 header
  with ``next_header == UDP`` is handled.
- Multi-segment mbufs are not supported. PTP event messages are
  typically less than 128 bytes and fit in a single segment.
- PTP over MPLS or other tunneling protocols is not supported.
