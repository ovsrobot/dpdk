/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_ETHDEV_H
#define APP_GRAPH_ETHDEV_H

#define ETHDEV_IPV6_ADDR_LEN	16

struct ipv4_addr_config {
	uint32_t ip;
	uint32_t mask;
};

struct ipv6_addr_config {
	uint8_t ip[ETHDEV_IPV6_ADDR_LEN];
	uint8_t mask[ETHDEV_IPV6_ADDR_LEN];
};

extern uint32_t enabled_port_mask;

void ethdev_start(void);
void ethdev_stop(void);
void *ethdev_mempool_list_by_portid(uint16_t portid);
int16_t ethdev_portid_by_ip4(uint32_t ip);
int16_t ethdev_portid_by_ip6(uint8_t *ip);

#endif
