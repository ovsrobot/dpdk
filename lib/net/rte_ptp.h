/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#ifndef _RTE_PTP_H_
#define _RTE_PTP_H_

/**
 * @file
 *
 * PTP (IEEE 1588) protocol definitions
 */

#include <stdint.h>
#include <stdbool.h>

#include <rte_byteorder.h>
#include <rte_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PTP Constants
 */

/** PTP over UDP event port (Sync, Delay_Req, PDelay_Req, PDelay_Resp). */
#define RTE_PTP_EVENT_PORT        319

/** PTP over UDP general port (Follow_Up, Delay_Resp, Announce, etc.). */
#define RTE_PTP_GENERAL_PORT      320

/** PTP multicast MAC address: 01:1B:19:00:00:00. */
#define RTE_PTP_MULTICAST_MAC     { 0x01, 0x1B, 0x19, 0x00, 0x00, 0x00 }

/** PTP peer delay multicast MAC: 01:80:C2:00:00:0E. */
#define RTE_PTP_PDELAY_MULTICAST_MAC { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E }

/*
 * PTP Message Types (IEEE 1588-2019 Table 36)
 */

#define RTE_PTP_MSGTYPE_SYNC            0x0  /**< Sync (event). */
#define RTE_PTP_MSGTYPE_DELAY_REQ       0x1  /**< Delay_Req (event). */
#define RTE_PTP_MSGTYPE_PDELAY_REQ      0x2  /**< Peer_Delay_Req (event). */
#define RTE_PTP_MSGTYPE_PDELAY_RESP     0x3  /**< Peer_Delay_Resp (event). */
#define RTE_PTP_MSGTYPE_FOLLOW_UP       0x8  /**< Follow_Up (general). */
#define RTE_PTP_MSGTYPE_DELAY_RESP      0x9  /**< Delay_Resp (general). */
#define RTE_PTP_MSGTYPE_PDELAY_RESP_FU  0xA  /**< Peer_Delay_Resp_Follow_Up. */
#define RTE_PTP_MSGTYPE_ANNOUNCE        0xB  /**< Announce (general). */
#define RTE_PTP_MSGTYPE_SIGNALING       0xC  /**< Signaling (general). */
#define RTE_PTP_MSGTYPE_MANAGEMENT      0xD  /**< Management (general). */

/*
 * PTP Flag Field Bits (IEEE 1588-2019 Table 37)
 *
 * These constants are for use after rte_be_to_cpu_16(hdr->flags).
 * flagField[0] (octet 6) maps to host bits 8-15.
 * flagField[1] (octet 7) maps to host bits 0-7.
 */

#define RTE_PTP_FLAG_TWO_STEP    (1 << 9)   /**< Two-step flag. */
#define RTE_PTP_FLAG_UNICAST     (1 << 10)  /**< Unicast flag. */
#define RTE_PTP_FLAG_LI_61       (1 << 0)   /**< Leap indicator 61. */
#define RTE_PTP_FLAG_LI_59       (1 << 1)   /**< Leap indicator 59. */

/*
 * PTP Header Structures (IEEE 1588-2019)
 */

/**
 * PTP Port Identity (10 bytes).
 */
struct __rte_packed_begin rte_ptp_port_id {
	uint8_t    clock_id[8]; /**< clockIdentity (EUI-64). */
	rte_be16_t port_number; /**< portNumber. */
} __rte_packed_end;

/**
 * PTP Common Message Header (34 bytes).
 */
struct __rte_packed_begin rte_ptp_hdr {
	uint8_t    msg_type;       /**< transportSpecific (4) | messageType (4). */
	uint8_t    version;        /**< minorVersionPTP (4) | versionPTP (4). */
	rte_be16_t msg_length;     /**< Total message length in bytes. */
	uint8_t    domain_number;  /**< PTP domain (0-255). */
	uint8_t    minor_sdo_id;   /**< minorSdoId (IEEE 1588-2019). */
	rte_be16_t flags;          /**< Flag field (see RTE_PTP_FLAG_*). */
	rte_be64_t correction;     /**< correctionField (scaled ns, 48.16 fixed). */
	rte_be32_t msg_type_specific; /**< messageTypeSpecific. */
	struct rte_ptp_port_id source_port_id; /**< sourcePortIdentity. */
	rte_be16_t sequence_id;    /**< sequenceId. */
	uint8_t    control;        /**< controlField (deprecated in 1588-2019). */
	int8_t     log_msg_interval; /**< logMessageInterval. */
} __rte_packed_end;

/**
 * PTP Timestamp (10 bytes, used in Sync/Delay_Req/Follow_Up bodies).
 */
struct __rte_packed_begin rte_ptp_timestamp {
	rte_be16_t seconds_hi;   /**< Upper 16 bits of seconds. */
	rte_be32_t seconds_lo;   /**< Lower 32 bits of seconds. */
	rte_be32_t nanoseconds;  /**< Nanoseconds (0-999999999). */
} __rte_packed_end;

/*
 * Inline Helpers
 */

/**
 * Extract PTP message type from header.
 *
 * @param hdr
 *   Pointer to PTP header.
 * @return
 *   Message type (0x0-0xF).
 */
static inline uint8_t
rte_ptp_msg_type(const struct rte_ptp_hdr *hdr)
{
	return hdr->msg_type & 0x0F;
}

/**
 * Extract transport-specific field from header.
 *
 * @param hdr
 *   Pointer to PTP header.
 * @return
 *   Transport-specific value (upper nibble, 0x0-0xF).
 */
static inline uint8_t
rte_ptp_transport_specific(const struct rte_ptp_hdr *hdr)
{
	return (hdr->msg_type >> 4) & 0x0F;
}

/**
 * Extract PTP version from header.
 *
 * @param hdr
 *   Pointer to PTP header.
 * @return
 *   PTP version number (typically 2).
 */
static inline uint8_t
rte_ptp_version(const struct rte_ptp_hdr *hdr)
{
	return hdr->version & 0x0F;
}

/**
 * Get sequence ID from PTP header (host byte order).
 *
 * @param hdr
 *   Pointer to PTP header.
 * @return
 *   Sequence ID in host byte order.
 */
static inline uint16_t
rte_ptp_seq_id(const struct rte_ptp_hdr *hdr)
{
	return rte_be_to_cpu_16(hdr->sequence_id);
}

/**
 * Get PTP domain number.
 *
 * @param hdr
 *   Pointer to PTP header.
 * @return
 *   Domain number (0-255).
 */
static inline uint8_t
rte_ptp_domain(const struct rte_ptp_hdr *hdr)
{
	return hdr->domain_number;
}

/**
 * Check if PTP message type is an event message.
 * Event messages (msg_type 0x0-0x3) require timestamps.
 *
 * @param msg_type
 *   PTP message type value (0x0-0xF).
 * @return
 *   true if event message, false otherwise.
 */
static inline bool
rte_ptp_is_event(int msg_type)
{
	return msg_type >= 0 && msg_type <= RTE_PTP_MSGTYPE_PDELAY_RESP;
}

/**
 * Check if the two-step flag is set in a PTP header.
 *
 * @param hdr
 *   Pointer to PTP header.
 * @return
 *   true if two-step flag is set.
 */
static inline bool
rte_ptp_is_two_step(const struct rte_ptp_hdr *hdr)
{
	return (rte_be_to_cpu_16(hdr->flags) & RTE_PTP_FLAG_TWO_STEP) != 0;
}

/**
 * Get correctionField value in nanoseconds (from 48.16 fixed-point).
 *
 * @param hdr
 *   Pointer to PTP header.
 * @return
 *   Correction value in nanoseconds.
 */
static inline int64_t
rte_ptp_correction_ns(const struct rte_ptp_hdr *hdr)
{
	return (int64_t)rte_be_to_cpu_64(hdr->correction) >> 16;
}

/**
 * Add a residence time (in nanoseconds) to the correctionField.
 * Used by Transparent Clocks to account for relay transit delay.
 * The correctionField uses IEEE 1588 scaled nanoseconds (48.16 fixed-point).
 *
 * @param hdr
 *   Pointer to PTP header (will be modified in-place).
 * @param residence_ns
 *   Residence time in nanoseconds to add.
 */
static inline void
rte_ptp_add_correction(struct rte_ptp_hdr *hdr, int64_t residence_ns)
{
	int64_t cf = (int64_t)rte_be_to_cpu_64(hdr->correction);

	cf += (int64_t)((uint64_t)residence_ns << 16);
	hdr->correction = rte_cpu_to_be_64(cf);
}

/**
 * Convert a PTP timestamp structure to nanoseconds since epoch.
 *
 * @param ts
 *   Pointer to PTP timestamp.
 * @return
 *   Time in nanoseconds since epoch.
 */
static inline uint64_t
rte_ptp_timestamp_to_ns(const struct rte_ptp_timestamp *ts)
{
	uint64_t sec = ((uint64_t)rte_be_to_cpu_16(ts->seconds_hi) << 32) |
		       rte_be_to_cpu_32(ts->seconds_lo);

	return sec * 1000000000ULL + rte_be_to_cpu_32(ts->nanoseconds);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PTP_H_ */
