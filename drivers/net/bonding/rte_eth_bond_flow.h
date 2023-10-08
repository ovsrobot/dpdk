/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Corigine, Inc.
 */

#ifndef _RTE_ETH_BOND_FLOW_H_
#define _RTE_ETH_BOND_FLOW_H_

#include <rte_flow.h>
#include <rte_flow_driver.h>

extern const struct rte_flow_ops bond_flow_ops;

struct rte_flow {
	TAILQ_ENTRY(rte_flow) next;
	struct rte_flow *flows[RTE_MAX_ETHPORTS];
	/**< Member ports flows */
	struct rte_flow_conv_rule rule;
	/**< Flow description for synchronization */
	uint8_t rule_data[];
};

#endif /* _RTE_ETH_BOND_FLOW_H_ */
