/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_FLOW_H_
#define _SSSNIC_ETHDEV_FLOW_H_

int sssnic_ethdev_flow_ops_get(struct rte_eth_dev *ethdev,
	const struct rte_flow_ops **ops);

#endif /* _SSSNIC_ETHDEV_FLOW_H_ */
