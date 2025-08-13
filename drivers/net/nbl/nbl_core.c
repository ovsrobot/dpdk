/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#include "nbl_core.h"

static struct nbl_product_core_ops nbl_product_core_ops[NBL_PRODUCT_MAX] = {
	{
		.phy_init	= nbl_phy_init_leonis_snic,
		.phy_remove	= nbl_phy_remove_leonis_snic,
		.res_init	= NULL,
		.res_remove	= NULL,
		.chan_init	= NULL,
		.chan_remove	= NULL,
	},
};

static struct nbl_product_core_ops *nbl_core_get_product_ops(enum nbl_product_type product_type)
{
	return &nbl_product_core_ops[product_type];
}

static void nbl_init_func_caps(struct rte_pci_device *pci_dev, struct nbl_func_caps *caps)
{
	if (pci_dev->id.device_id >= NBL_DEVICE_ID_M18110 &&
	    pci_dev->id.device_id <= NBL_DEVICE_ID_M18100_VF)
		caps->product_type = NBL_LEONIS_TYPE;
}

int nbl_core_init(struct nbl_adapter *adapter, struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct nbl_product_core_ops *product_base_ops = NULL;
	int ret = 0;

	nbl_init_func_caps(pci_dev, &adapter->caps);

	product_base_ops = nbl_core_get_product_ops(adapter->caps.product_type);

	/* every product's phy/chan/res layer has a great difference, so call their own init ops */
	ret = product_base_ops->phy_init(adapter);
	if (ret)
		goto phy_init_fail;

	return 0;

phy_init_fail:
	return -EINVAL;
}

void nbl_core_remove(struct nbl_adapter *adapter)
{
	struct nbl_product_core_ops *product_base_ops = NULL;

	product_base_ops = nbl_core_get_product_ops(adapter->caps.product_type);

	product_base_ops->phy_remove(adapter);
}

int nbl_core_start(struct nbl_adapter *adapter)
{
	RTE_SET_USED(adapter);

	return 0;
}

void nbl_core_stop(struct nbl_adapter *adapter)
{
	RTE_SET_USED(adapter);
}
