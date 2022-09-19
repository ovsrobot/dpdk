/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell International Ltd.
 */

#include <stdint.h>

#include <rte_errno.h>
#include "rte_ethdev.h"
#include "ethdev_driver.h"

static int
eth_err(uint16_t port_id, int ret)
{
	if (ret == 0)
		return 0;

	if (rte_eth_dev_is_removed(port_id))
		return -EIO;

	return ret;
}

#define RTE_CMAN_FUNC_ERR_RET(func)					\
do {									\
	if (func == NULL) {						\
		RTE_ETHDEV_LOG(ERR, "Function not implemented\n");	\
		return -ENOTSUP;					\
	}								\
} while (0)

/* Get congestion management information for a port */
int
rte_eth_cman_info_get(uint16_t port_id, struct rte_eth_cman_info *info)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];

	if (info == NULL) {
		RTE_ETHDEV_LOG(ERR, "congestion management info is NULL\n");
		return -EINVAL;
	}

	RTE_CMAN_FUNC_ERR_RET(dev->dev_ops->cman_info_get);
	return eth_err(port_id, (*dev->dev_ops->cman_info_get)(dev, info));
}

/* Initialize congestion management structure with default values */
int
rte_eth_cman_config_init(uint16_t port_id, struct rte_eth_cman_config *config)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];

	if (config == NULL) {
		RTE_ETHDEV_LOG(ERR, "congestion management config is NULL\n");
		return -EINVAL;
	}

	RTE_CMAN_FUNC_ERR_RET(dev->dev_ops->cman_config_init);
	return eth_err(port_id, (*dev->dev_ops->cman_config_init)(dev, config));
}

/* Configure congestion management on a port */
int
rte_eth_cman_config_set(uint16_t port_id, struct rte_eth_cman_config *config)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];

	if (config == NULL) {
		RTE_ETHDEV_LOG(ERR, "congestion management config is NULL\n");
		return -EINVAL;
	}

	RTE_CMAN_FUNC_ERR_RET(dev->dev_ops->cman_config_set);
	return eth_err(port_id, (*dev->dev_ops->cman_config_set)(dev, config));
}

/* Retrieve congestion management configuration of a port */
int
rte_eth_cman_config_get(uint16_t port_id, struct rte_eth_cman_config *config)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];

	if (config == NULL) {
		RTE_ETHDEV_LOG(ERR, "congestion management config is NULL\n");
		return -EINVAL;
	}

	RTE_CMAN_FUNC_ERR_RET(dev->dev_ops->cman_config_get);
	return eth_err(port_id, (*dev->dev_ops->cman_config_get)(dev, config));
}
