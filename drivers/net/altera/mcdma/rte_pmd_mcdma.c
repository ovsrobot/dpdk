/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2026 Altera Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <eal_export.h>
#include <ethdev_driver.h>
#include <rte_compat.h>

#include "mcdma_eth.h"
#include "rte_pmd_mcdma.h"

#define MCDMA_PMD_NAME "net_mcdma"

static int
mcdma_pmd_port_get(uint16_t port_id, struct rte_eth_dev **eth_dev)
{
	struct rte_eth_dev *dev;

	if (eth_dev == NULL)
		return -EINVAL;

	if (!rte_eth_dev_is_valid_port(port_id))
		return -EINVAL;

	dev = &rte_eth_devices[port_id];
	if (dev->state != RTE_ETH_DEV_ATTACHED)
		return -ENODEV;

	if (dev->device == NULL || dev->device->driver == NULL ||
	    strcmp(dev->device->driver->name, MCDMA_PMD_NAME) != 0)
		return -ENODEV;

	*eth_dev = dev;
	return 0;
}

static int
mcdma_pio_offset_check(const struct mcdma_pci_device *priv, uint64_t offset)
{
	if (priv->pio == NULL || priv->pio_bar_len == 0)
		return -ENODEV;

	if ((offset & (sizeof(uint64_t) - 1)) != 0)
		return -EINVAL;

	if (priv->pio_bar_len < sizeof(uint64_t) ||
	    offset > priv->pio_bar_len - sizeof(uint64_t))
		return -EINVAL;

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_mcdma_pio_read64, 26.11)
int
rte_pmd_mcdma_pio_read64(uint16_t port_id, uint64_t offset, uint64_t *val)
{
	struct rte_eth_dev *dev;
	struct mcdma_pci_device *priv;
	int ret;

	if (val == NULL)
		return -EINVAL;

	ret = mcdma_pmd_port_get(port_id, &dev);
	if (ret != 0)
		return ret;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	ret = mcdma_pio_offset_check(priv, offset);
	if (ret != 0)
		return ret;

	*val = mcdma_pio_reg_read64(priv->pio, offset);
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_mcdma_pio_write64, 26.11)
int
rte_pmd_mcdma_pio_write64(uint16_t port_id, uint64_t offset, uint64_t val)
{
	struct rte_eth_dev *dev;
	struct mcdma_pci_device *priv;
	int ret;

	ret = mcdma_pmd_port_get(port_id, &dev);
	if (ret != 0)
		return ret;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	ret = mcdma_pio_offset_check(priv, offset);
	if (ret != 0)
		return ret;

	mcdma_pio_reg_write64(priv->pio, offset, val);
	return 0;
}
