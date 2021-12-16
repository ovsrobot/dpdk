/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

struct ipv4_5tuple {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __rte_packed;

struct ipv6_5tuple {
	union {
		uint8_t  ip_dst[IPV6_ADDR_LEN];
		uint32_t ip32_dst[4];
	};
	union {
		uint8_t  ip_src[IPV6_ADDR_LEN];
		uint32_t ip32_src[4];
	};
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __rte_packed;

struct lpm_route_rule {
	union {
		uint32_t ip;
		union {
			uint32_t ip_32[4];
			uint8_t ip_8[16];
		};
	};
	uint8_t depth;
	uint8_t if_out;
};

struct em_rule {
		union {
		struct ipv4_5tuple v4_key;
		struct ipv6_5tuple v6_key;
	};
	uint8_t if_out;
};

extern struct lpm_route_rule *route_base_v4;
extern struct lpm_route_rule *route_base_v6;
extern int route_num_v4;
extern int route_num_v6;
