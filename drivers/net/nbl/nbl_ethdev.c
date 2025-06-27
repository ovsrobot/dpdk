/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#include "nbl_ethdev.h"

RTE_LOG_REGISTER_SUFFIX(nbl_logtype_init, init, INFO);
RTE_LOG_REGISTER_SUFFIX(nbl_logtype_driver, driver, INFO);

static int nbl_dev_release_pf(struct rte_eth_dev *eth_dev)
{
	struct nbl_adapter *adapter = ETH_DEV_TO_NBL_DEV_PF_PRIV(eth_dev);

	if (!adapter)
		return -EINVAL;
	NBL_LOG(INFO, "start to close device %s", eth_dev->device->name);
	nbl_core_stop(adapter);
	nbl_core_remove(adapter);
	return 0;
}

static int nbl_dev_close(struct rte_eth_dev *eth_dev)
{
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;

	return nbl_dev_release_pf(eth_dev);
}

struct eth_dev_ops nbl_eth_dev_ops = {
	.dev_close = nbl_dev_close,
};

#define NBL_DEV_NET_OPS_TBL						\
do {									\
	NBL_DEV_NET_OPS(dev_configure,		dev_ops->dev_configure);\
	NBL_DEV_NET_OPS(dev_start,		dev_ops->dev_start);	\
	NBL_DEV_NET_OPS(dev_stop,		dev_ops->dev_stop);	\
} while (0)

static void nbl_set_eth_dev_ops(struct nbl_adapter *adapter,
				struct eth_dev_ops *nbl_eth_dev_ops)
{
	struct nbl_dev_ops_tbl *dev_ops_tbl;
	struct nbl_dev_ops *dev_ops;
	static bool inited;

	if (!inited) {
		dev_ops_tbl = NBL_ADAPTER_TO_DEV_OPS_TBL(adapter);
		dev_ops = NBL_DEV_OPS_TBL_TO_OPS(dev_ops_tbl);
#define NBL_DEV_NET_OPS(ops, func)				\
	do {nbl_eth_dev_ops->NBL_NAME(ops) = func; ; } while (0)
			NBL_DEV_NET_OPS_TBL;
#undef  NBL_DEV_NET_OPS
		inited = true;
	}
}

static int nbl_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct nbl_adapter *adapter = ETH_DEV_TO_NBL_DEV_PF_PRIV(eth_dev);
	int ret;

	PMD_INIT_FUNC_TRACE();
	ret = nbl_core_init(adapter, eth_dev);
	if (ret) {
		NBL_LOG(INFO, "core init failed ret %d", ret);
		goto eth_init_failed;
	}

	ret = nbl_core_start(adapter);
	if (ret) {
		NBL_LOG(INFO, "core start failed ret %d", ret);
		nbl_core_remove(adapter);
		goto eth_init_failed;
	}

	nbl_set_eth_dev_ops(adapter, &nbl_eth_dev_ops);
	eth_dev->dev_ops = &nbl_eth_dev_ops;
	return 0;

eth_init_failed:
	return ret;
}

/**
 * @brief: nbl device pci probe
 * @param[in]: {rte_pci_driver} *pci_drv
 * @param[in]: {rte_pci_device} *pci_dev
 * @return: {0-success,negative-fail}
 */
static int nbl_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			 struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev, sizeof(struct nbl_adapter),
					     nbl_eth_dev_init);
}

static int nbl_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
	PMD_INIT_FUNC_TRACE();
	return nbl_dev_close(eth_dev);
}

static int nbl_pci_remove(struct rte_pci_device *pci_dev)
{
	PMD_INIT_FUNC_TRACE();
	return rte_eth_dev_pci_generic_remove(pci_dev, nbl_eth_dev_uninit);
}

static const struct rte_pci_id pci_id_nbl_map[] = {
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_BASE_T) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_BASE_T) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_OCP) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_OCP) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_BASE_T_OCP) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_BASE_T_OCP) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_LX) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_BASE_T) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_LX_BASE_T) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_OCP) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_LX_OCP) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_BASE_T_OCP) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_LX_BASE_T_OCP) },
	{ RTE_PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18100_VF) },
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver nbl_pmd = {
	.id_table = pci_id_nbl_map,
	.drv_flags =
		RTE_PCI_DRV_INTR_LSC |
		RTE_PCI_DRV_PROBE_AGAIN,
	.probe = nbl_pci_probe,
	.remove = nbl_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_nbl, nbl_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_nbl, pci_id_nbl_map);
