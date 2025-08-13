/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#include "nbl_phy_leonis_snic.h"

static inline void nbl_wr32(void *priv, u64 reg, u32 value)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	rte_write32(rte_cpu_to_le_32(value), ((phy_mgt)->hw_addr + (reg)));
}

static void nbl_phy_update_tail_ptr(void *priv, u16 notify_qid, u16 tail_ptr)
{
	nbl_wr32(priv, NBL_NOTIFY_ADDR, ((u32)tail_ptr << NBL_TAIL_PTR_OFT | (u32)notify_qid));
}

static u8 *nbl_phy_get_tail_ptr(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return phy_mgt->hw_addr;
}

static struct nbl_phy_ops phy_ops = {
	.update_tail_ptr		= nbl_phy_update_tail_ptr,
	.get_tail_ptr			= nbl_phy_get_tail_ptr,
};

static int nbl_phy_setup_ops(struct nbl_phy_ops_tbl **phy_ops_tbl,
			     struct nbl_phy_mgt_leonis_snic *phy_mgt_leonis_snic)
{
	*phy_ops_tbl = rte_zmalloc("nbl_phy_ops", sizeof(struct nbl_phy_ops_tbl), 0);
	if (!*phy_ops_tbl)
		return -ENOMEM;

	NBL_PHY_OPS_TBL_TO_OPS(*phy_ops_tbl) = &phy_ops;
	NBL_PHY_OPS_TBL_TO_PRIV(*phy_ops_tbl) = phy_mgt_leonis_snic;

	return 0;
}

static void nbl_phy_remove_ops(struct nbl_phy_ops_tbl **phy_ops_tbl)
{
	rte_free(*phy_ops_tbl);
	*phy_ops_tbl = NULL;
}

int nbl_phy_init_leonis_snic(void *p)
{
	struct nbl_phy_mgt_leonis_snic **phy_mgt_leonis_snic;
	struct nbl_phy_mgt *phy_mgt;
	struct nbl_phy_ops_tbl **phy_ops_tbl;
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct rte_pci_device *pci_dev = adapter->pci_dev;
	int ret = 0;

	phy_mgt_leonis_snic = (struct nbl_phy_mgt_leonis_snic **)&NBL_ADAPTER_TO_PHY_MGT(adapter);
	phy_ops_tbl = &NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);

	*phy_mgt_leonis_snic = rte_zmalloc("nbl_phy_mgt",
					   sizeof(struct nbl_phy_mgt_leonis_snic), 0);
	if (!*phy_mgt_leonis_snic) {
		ret = -ENOMEM;
		goto alloc_phy_mgt_failed;
	}

	phy_mgt = &(*phy_mgt_leonis_snic)->phy_mgt;

	phy_mgt->hw_addr = (u8 *)pci_dev->mem_resource[0].addr;
	phy_mgt->memory_bar_pa = pci_dev->mem_resource[0].phys_addr;
	phy_mgt->mailbox_bar_hw_addr = (u8 *)pci_dev->mem_resource[2].addr;

	ret = nbl_phy_setup_ops(phy_ops_tbl, *phy_mgt_leonis_snic);
	if (ret)
		goto setup_ops_failed;

	return ret;

setup_ops_failed:
	rte_free(*phy_mgt_leonis_snic);
alloc_phy_mgt_failed:
	return ret;
}

void nbl_phy_remove_leonis_snic(void *p)
{
	struct nbl_phy_mgt_leonis_snic **phy_mgt_leonis_snic;
	struct nbl_phy_ops_tbl **phy_ops_tbl;
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;

	phy_mgt_leonis_snic = (struct nbl_phy_mgt_leonis_snic **)&adapter->core.phy_mgt;
	phy_ops_tbl = &NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);

	rte_free(*phy_mgt_leonis_snic);

	nbl_phy_remove_ops(phy_ops_tbl);
}
