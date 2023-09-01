/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_LINK_H_
#define _SSSNIC_ETHDEV_LINK_H_

int sssnic_ethdev_set_link_up(struct rte_eth_dev *ethdev);
int sssnic_ethdev_set_link_down(struct rte_eth_dev *ethdev);
int sssnic_ethdev_link_update(struct rte_eth_dev *ethdev, int wait_to_complete);
void sssnic_ethdev_link_intr_enable(struct rte_eth_dev *ethdev);
void sssnic_ethdev_link_intr_disable(struct rte_eth_dev *ethdev);

#endif /* _SSSNIC_ETHDEV_LINK_H_ */
