/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Siemens AG
 */
#include <rte_ether.h>

#ifndef _L2REFLECT_PAYLOAD_H_
#define _L2REFLECT_PAYLOAD_H_

#define MAGIC_TRACE_PAYLOAD 0xd00faffeaffed00full
/* IEEE Std 802 - Local Experimental Ethertype */
#define ETHER_TYPE_L2REFLECT 0x88B5

struct my_magic_packet {
	/* l2 packet header */
	struct rte_ether_hdr eth;
	/* type of the l2reflect packet */
	uint8_t type;
	/* magic easy-to-spot pattern for tracing */
	uint64_t magic;
	/* break if latency is larger than this */
	uint64_t breakval;
	/* intended size of the packet */
	uint64_t req_pkt_bytes;
};

#endif /* _L2REFLECT_PAYLOAD_H_ */
