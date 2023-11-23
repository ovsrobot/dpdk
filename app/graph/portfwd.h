/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_PORTFWD_H
#define APP_GRAPH_PORTFWD_H

extern cmdline_parse_inst_t ethdev_forward_cmd_ctx;

struct port_forwarding {
	TAILQ_ENTRY(port_forwarding) next;
	uint16_t tx_port;
	uint16_t rx_port;
	bool is_used;
} __rte_cache_aligned;

TAILQ_HEAD(prt_fw, port_forwarding);

struct port_forwarding *find_pf_entry_rx_port(uint16_t portid_rx);

#endif
