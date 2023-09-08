/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_NEIGH_PRIV_H
#define APP_GRAPH_NEIGH_PRIV_H

#define MAX_NEIGH_ENTRIES 32

struct ipv4_neigh_config {
	uint32_t ip;
	uint64_t mac;
	bool is_used;
};

struct ipv6_neigh_config {
	uint8_t ip[16];
	uint64_t mac;
	bool is_used;
};

#endif
