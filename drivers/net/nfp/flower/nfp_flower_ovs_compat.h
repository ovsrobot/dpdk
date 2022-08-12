/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#ifndef _NFP_FLOWER_OVS_COMPAT_H_
#define _NFP_FLOWER_OVS_COMPAT_H_

enum dp_packet_source {
	DPBUF_MALLOC,              /* Obtained via malloc(). */
	DPBUF_STACK,               /* Un-movable stack space or static buffer. */
	DPBUF_STUB,                /* Starts on stack, may expand into heap. */
	DPBUF_DPDK,                /* buffer data is from DPDK allocated memory. */
	DPBUF_AFXDP,               /* Buffer data from XDP frame. */
};

#define DP_PACKET_CONTEXT_SIZE 64

/*
 * Buffer for holding packet data.  A dp_packet is automatically reallocated
 * as necessary if it grows too large for the available memory.
 * By default the packet type is set to Ethernet (0).
 */
struct dp_packet {
	struct rte_mbuf mbuf;          /* DPDK mbuf */
	enum dp_packet_source source;  /* Source of memory allocated as 'base'. */

	uint16_t l2_pad_size;          /* Detected l2 padding size. Padding is non-pullable. */
	uint16_t l2_5_ofs;             /* MPLS label stack offset, or UINT16_MAX */
	uint16_t l3_ofs;               /* Network-level header offset, or UINT16_MAX. */
	uint16_t l4_ofs;               /* Transport-level header offset, or UINT16_MAX. */
	uint32_t cutlen;               /* length in bytes to cut from the end. */
	uint32_t packet_type;          /* Packet type as defined in OpenFlow */
	uint64_t data[DP_PACKET_CONTEXT_SIZE / 8];
};

#endif /* _NFP_FLOWER_OVS_COMPAT_ */
