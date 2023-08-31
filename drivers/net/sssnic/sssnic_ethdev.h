/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_H_
#define _SSSNIC_ETHDEV_H_

struct sssnic_netdev {
	void *hw;
};

#define SSSNIC_ETHDEV_PRIVATE(eth_dev)                                         \
	((struct sssnic_netdev *)(eth_dev)->data->dev_private)
#define SSSNIC_NETDEV_TO_HW(netdev) ((struct sssnic_hw *)(netdev)->hw)
#define SSSNIC_ETHDEV_TO_HW(eth_dev)                                           \
	SSSNIC_NETDEV_TO_HW(SSSNIC_ETHDEV_PRIVATE(eth_dev))

#endif /*_SSSNIC_ETHDEV_H_*/
