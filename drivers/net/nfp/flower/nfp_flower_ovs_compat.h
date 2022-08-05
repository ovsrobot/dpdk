/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#ifndef _NFP_FLOWER_OVS_COMPAT_H_
#define _NFP_FLOWER_OVS_COMPAT_H_

/* From ovs */
#define PAD_PASTE2(x, y) x##y
#define PAD_PASTE(x, y) PAD_PASTE2(x, y)
#define PAD_ID PAD_PASTE(pad, __COUNTER__)

/* Returns X rounded up to the nearest multiple of Y. */
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))

typedef uint8_t OVS_CACHE_LINE_MARKER[1];

#ifndef __cplusplus
#define PADDED_MEMBERS_CACHELINE_MARKER(UNIT, CACHELINE, MEMBERS)   \
	union {                                                         \
		OVS_CACHE_LINE_MARKER CACHELINE;                            \
		struct { MEMBERS };                                         \
		uint8_t PAD_ID[ROUND_UP(sizeof(struct { MEMBERS }), UNIT)]; \
	}
#else
#define PADDED_MEMBERS_CACHELINE_MARKER(UNIT, CACHELINE, MEMBERS)           \
	struct struct_##CACHELINE { MEMBERS };                                  \
	union {                                                                 \
		OVS_CACHE_LINE_MARKER CACHELINE;                                    \
		struct { MEMBERS };                                                 \
		uint8_t PAD_ID[ROUND_UP(sizeof(struct struct_##CACHELINE), UNIT)];  \
	}
#endif

struct ovs_key_ct_tuple_ipv4 {
	rte_be32_t ipv4_src;
	rte_be32_t ipv4_dst;
	rte_be16_t src_port;
	rte_be16_t dst_port;
	uint8_t    ipv4_proto;
};

struct ovs_key_ct_tuple_ipv6 {
	rte_be32_t ipv6_src[4];
	rte_be32_t ipv6_dst[4];
	rte_be16_t src_port;
	rte_be16_t dst_port;
	uint8_t    ipv6_proto;
};

/* Tunnel information used in flow key and metadata. */
struct flow_tnl {
	uint32_t ip_dst;
	struct in6_addr ipv6_dst;
	uint32_t ip_src;
	struct in6_addr ipv6_src;
	uint64_t tun_id;
	uint16_t flags;
	uint8_t ip_tos;
	uint8_t ip_ttl;
	uint16_t tp_src;
	uint16_t tp_dst;
	uint16_t gbp_id;
	uint8_t  gbp_flags;
	uint8_t erspan_ver;
	uint32_t erspan_idx;
	uint8_t erspan_dir;
	uint8_t erspan_hwid;
	uint8_t gtpu_flags;
	uint8_t gtpu_msgtype;
	uint8_t pad1[4];     /* Pad to 64 bits. */
};

enum dp_packet_source {
	DPBUF_MALLOC,              /* Obtained via malloc(). */
	DPBUF_STACK,               /* Un-movable stack space or static buffer. */
	DPBUF_STUB,                /* Starts on stack, may expand into heap. */
	DPBUF_DPDK,                /* buffer data is from DPDK allocated memory. */
	DPBUF_AFXDP,               /* Buffer data from XDP frame. */
};

/* Datapath packet metadata */
struct pkt_metadata {
PADDED_MEMBERS_CACHELINE_MARKER(RTE_CACHE_LINE_SIZE, cacheline0,
	/* Recirculation id carried with the recirculating packets. */
	uint32_t recirc_id;         /* 0 for packets received from the wire. */
	uint32_t dp_hash;           /* hash value computed by the recirculation action. */
	uint32_t skb_priority;      /* Packet priority for QoS. */
	uint32_t pkt_mark;          /* Packet mark. */
	uint8_t  ct_state;          /* Connection state. */
	bool ct_orig_tuple_ipv6;
	uint16_t ct_zone;           /* Connection zone. */
	uint32_t ct_mark;           /* Connection mark. */
	uint32_t ct_label[4];       /* Connection label. */
	uint32_t in_port;           /* Input port. */
	uint32_t orig_in_port;      /* Originating in_port for tunneled packets */
	void *conn;                 /* Cached conntrack connection. */
	bool reply;                 /* True if reply direction. */
	bool icmp_related;          /* True if ICMP related. */
);

PADDED_MEMBERS_CACHELINE_MARKER(RTE_CACHE_LINE_SIZE, cacheline1,
	union {                     /* Populated only for non-zero 'ct_state'. */
		struct ovs_key_ct_tuple_ipv4 ipv4;
		struct ovs_key_ct_tuple_ipv6 ipv6;   /* Used only if */
	} ct_orig_tuple;                             /* 'ct_orig_tuple_ipv6' is set */
);

/*
 * Encapsulating tunnel parameters. Note that if 'ip_dst' == 0,
 * the rest of the fields may be uninitialized.
 */
PADDED_MEMBERS_CACHELINE_MARKER(RTE_CACHE_LINE_SIZE, cacheline2,
	struct flow_tnl tunnel;);
};

#define DP_PACKET_CONTEXT_SIZE 64

/*
 * Buffer for holding packet data.  A dp_packet is automatically reallocated
 * as necessary if it grows too large for the available memory.
 * By default the packet type is set to Ethernet (PT_ETH).
 */
struct dp_packet {
	struct rte_mbuf mbuf;          /* DPDK mbuf */
	enum dp_packet_source source;  /* Source of memory allocated as 'base'. */

	/*
	 * All the following elements of this struct are copied in a single call
	 * of memcpy in dp_packet_clone_with_headroom.
	 */
	uint16_t l2_pad_size;          /* Detected l2 padding size. Padding is non-pullable. */
	uint16_t l2_5_ofs;             /* MPLS label stack offset, or UINT16_MAX */
	uint16_t l3_ofs;               /* Network-level header offset, or UINT16_MAX. */
	uint16_t l4_ofs;               /* Transport-level header offset, or UINT16_MAX. */
	uint32_t cutlen;               /* length in bytes to cut from the end. */
	uint32_t packet_type;          /* Packet type as defined in OpenFlow */
	union {
		struct pkt_metadata md;
		uint64_t data[DP_PACKET_CONTEXT_SIZE / 8];
	};
};

#endif /* _NFP_FLOWER_OVS_COMPAT_ */
