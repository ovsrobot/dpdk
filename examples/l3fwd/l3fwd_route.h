/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

struct ipv4_l3fwd_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  if_out;
};

struct ipv6_l3fwd_route {
	uint8_t ip[16];
	uint8_t depth;
	uint8_t if_out;
};

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

extern struct lpm_route_rule *route_base_v4;
extern struct lpm_route_rule *route_base_v6;
extern int route_num_v4;
extern int route_num_v6;
