/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
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

#define NGBE_VMDQ_NUM_UC_MAC         4096 /* Maximum nb. of UC MAC addr. */

#endif /* _NGBE_ETHDEV_H_ */
