/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020
 */

#ifndef _NGBE_ETHDEV_H_
#define _NGBE_ETHDEV_H_

/*
 * Structure to store private data for each driver instance (for each port).
 */
struct ngbe_adapter {
	struct ngbe_hw             hw;
};

#define NGBE_DEV_ADAPTER(dev) \
	((struct ngbe_adapter *)(dev)->data->dev_private)

#define NGBE_DEV_HW(dev) \
	(&((struct ngbe_adapter *)(dev)->data->dev_private)->hw)

#endif /* _NGBE_ETHDEV_H_ */
