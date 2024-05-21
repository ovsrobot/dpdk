/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#ifndef _TAP_RSS_H_
#define _TAP_RSS_H_

#ifndef TAP_MAX_QUEUES
#define TAP_MAX_QUEUES 16
#endif

/* Fixed RSS hash key size in bytes. */
#define TAP_RSS_HASH_KEY_SIZE 40

/* Supported RSS */
#define TAP_RSS_HF_MASK (~(RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP))

/* hashed fields for RSS */
enum hash_field {
	HASH_FIELD_IPV4_L3,	/* IPv4 src/dst addr */
	HASH_FIELD_IPV4_L3_L4,	/* IPv4 src/dst addr + L4 src/dst ports */
	HASH_FIELD_IPV6_L3,	/* IPv6 src/dst addr */
	HASH_FIELD_IPV6_L3_L4,	/* IPv6 src/dst addr + L4 src/dst ports */
};

struct rss_key {
	 __u8 key[128];
	__u32 hash_fields;
	__u32 key_size;
	__u32 queues[TAP_MAX_QUEUES];
	__u32 nb_queues;
} __attribute__((packed));

#endif /* _TAP_RSS_H_ */
