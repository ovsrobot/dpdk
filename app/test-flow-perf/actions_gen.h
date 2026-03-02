/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 *
 * This file contains the functions definitions to
 * generate each supported action.
 */

#ifndef FLOW_PERF_ACTION_GEN
#define FLOW_PERF_ACTION_GEN

#include <rte_flow.h>

#include "config.h"

#define RTE_IP_TYPE_UDP	17
#define RTE_IP_TYPE_GRE	47
#define RTE_VXLAN_GPE_UDP_PORT 250
#define RTE_GENEVE_UDP_PORT 6081

/* Compound action data structures (needed by async_flow.c for slot init) */

/* Storage for struct rte_flow_action_raw_encap including external data. */
struct action_raw_encap_data {
	struct rte_flow_action_raw_encap conf;
	uint8_t data[128];
	uint8_t preserve[128];
	uint16_t idx;
};

/* Storage for struct rte_flow_action_raw_decap including external data. */
struct action_raw_decap_data {
	struct rte_flow_action_raw_decap conf;
	uint8_t data[128];
	uint16_t idx;
};

/* Storage for struct rte_flow_action_rss including external data. */
struct action_rss_data {
	struct rte_flow_action_rss conf;
	uint8_t key[40];
	uint16_t queue[128];
};

void fill_actions(struct rte_flow_action *actions, uint64_t *flow_actions,
	uint32_t counter, uint16_t next_table, uint16_t hairpinq,
	uint64_t encap_data, uint64_t decap_data, uint8_t core_idx,
	bool unique_data, uint8_t rx_queues_count, uint16_t dst_port);

/* Fill actions template for async flow API (types only, no values) */
void fill_actions_template(struct rte_flow_action *actions, struct rte_flow_action *masks,
			   uint64_t *flow_actions, struct rte_flow_port_attr *port_attr,
			   bool *need_wire_orig_table);

size_t action_conf_size(enum rte_flow_action_type type);

#endif /* FLOW_PERF_ACTION_GEN */
