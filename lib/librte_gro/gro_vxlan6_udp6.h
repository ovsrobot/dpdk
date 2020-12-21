/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Inspur Corporation
 */

#ifndef _GRO_VXLAN6_UDP6_H_
#define _GRO_VXLAN6_UDP6_H_

#include "gro_udp6.h"

#define GRO_VXLAN6_UDP6_TBL_MAX_ITEM_NUM (1024UL * 1024UL)

/* Header fields representing a IPv6 VxLAN flow */
struct vxlan6_udp6_flow_key {
	struct udp6_flow_key inner_key;
	struct rte_vxlan_hdr vxlan_hdr;

	struct rte_ether_addr outer_eth_saddr;
	struct rte_ether_addr outer_eth_daddr;

	uint8_t outer_ip_saddr[16];
	uint8_t outer_ip_daddr[16];

	/* Outer UDP ports */
	uint16_t outer_src_port;
	uint16_t outer_dst_port;

};

struct gro_vxlan6_udp6_flow {
	struct vxlan6_udp6_flow_key key;
	/*
	 * The index of the first packet in the flow. INVALID_ARRAY_INDEX
	 * indicates an empty flow.
	 */
	uint32_t start_index;
};

struct gro_vxlan6_udp6_item {
	struct gro_udp6_item inner_item;
};

/*
 * IPv6 VxLAN (with an outer IPv6 header and an inner UDP/IPv6 packet)
 * reassembly table structure
 */
struct gro_vxlan6_udp6_tbl {
	/* item array */
	struct gro_vxlan6_udp6_item *items;
	/* flow array */
	struct gro_vxlan6_udp6_flow *flows;
	/* current item number */
	uint32_t item_num;
	/* current flow number */
	uint32_t flow_num;
	/* the maximum item number */
	uint32_t max_item_num;
	/* the maximum flow number */
	uint32_t max_flow_num;
};

/**
 * This function creates a IPv6 VxLAN reassembly table for IPv6 VxLAN packets
 * which have an outer IPv6 header and an inner UDP/IPv6 packet.
 *
 * @param socket_id
 *  Socket index for allocating the table
 * @param max_flow_num
 *  The maximum number of flows in the table
 * @param max_item_per_flow
 *  The maximum number of packets per flow
 *
 * @return
 *  - Return the table pointer on success.
 *  - Return NULL on failure.
 */
void *gro_vxlan6_udp6_tbl_create(uint16_t socket_id,
		uint16_t max_flow_num,
		uint16_t max_item_per_flow);

/**
 * This function destroys a IPv6 VxLAN reassembly table.
 *
 * @param tbl
 *  Pointer pointing to the IPv6 VxLAN reassembly table
 */
void gro_vxlan6_udp6_tbl_destroy(void *tbl);

/**
 * This function merges a IPv6 VxLAN packet which has an outer IPv6 header and
 * an inner UDP/IPv6 packet. It does not process the packet which does not
 * have payload.
 *
 * This function does not check if the packet has correct checksums and
 * does not re-calculate checksums for the merged packet. It returns the
 * packet if there is no available space in the table.
 *
 * @param pkt
 *  Packet to reassemble
 * @param tbl
 *  Pointer pointing to the IPv6 VxLAN reassembly table
 * @start_time
 *  The time when the packet is inserted into the table
 *
 * @return
 *  - Return a positive value if the packet is merged.
 *  - Return zero if the packet isn't merged but stored in the table.
 *  - Return a negative value for invalid parameters or no available
 *    space in the table.
 */
int32_t gro_vxlan6_udp6_reassemble(struct rte_mbuf *pkt,
		struct gro_vxlan6_udp6_tbl *tbl,
		uint64_t start_time);

/**
 * This function flushes timeout packets in the IPv6 VxLAN reassembly table,
 * and without updating checksums.
 *
 * @param tbl
 *  Pointer pointing to a IPv6 VxLAN GRO table
 * @param flush_timestamp
 *  This function flushes packets which are inserted into the table
 *  before or at the flush_timestamp.
 * @param out
 *  Pointer array used to keep flushed packets
 * @param nb_out
 *  The element number in 'out'. It also determines the maximum number of
 *  packets that can be flushed finally.
 *
 * @return
 *  The number of flushed packets
 */
uint16_t gro_vxlan6_udp6_tbl_timeout_flush(struct gro_vxlan6_udp6_tbl *tbl,
		uint64_t flush_timestamp,
		struct rte_mbuf **out,
		uint16_t nb_out);

/**
 * This function returns the number of the packets in a IPv6 VxLAN
 * reassembly table.
 *
 * @param tbl
 *  Pointer pointing to the IPv6 VxLAN reassembly table
 *
 * @return
 *  The number of packets in the table
 */
uint32_t gro_vxlan6_udp6_tbl_pkt_count(void *tbl);
#endif
