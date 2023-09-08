/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_ROUTE_H
#define APP_GRAPH_ROUTE_H

#define MAX_ROUTE_ENTRIES 32

struct ipv4_route_config {
	uint32_t ip;
	uint32_t netmask;
	uint32_t via;
	bool is_used;
};

struct ipv6_route_config {
	uint8_t ip[16];
	uint8_t mask[16];
	uint8_t gateway[16];
	bool is_used;
};

extern struct ipv4_route_config route4[MAX_ROUTE_ENTRIES];
extern struct ipv6_route_config route6[MAX_ROUTE_ENTRIES];

int route_ip4_add_to_lookup(void);
int route_ip6_add_to_lookup(void);

#endif
