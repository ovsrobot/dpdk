/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#include "nbl_phy_leonis_snic.h"

static inline void nbl_wr32(void *priv, u64 reg, u32 value)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	rte_write32(rte_cpu_to_le_32(value), ((phy_mgt)->hw_addr + (reg)));
}

static inline u32 nbl_mbx_rd32(struct nbl_phy_mgt *phy_mgt, u64 reg)
{
	return rte_le_to_cpu_32(rte_read32(phy_mgt->mailbox_bar_hw_addr + reg));
}

static inline void nbl_mbx_wr32(void *priv, u64 reg, u32 value)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	rte_write32(rte_cpu_to_le_32(value), ((phy_mgt)->mailbox_bar_hw_addr + (reg)));
	rte_delay_us(NBL_DELAY_MIN_TIME_FOR_REGS);
}

static void nbl_hw_read_mbx_regs(struct nbl_phy_mgt *phy_mgt, u64 reg,
				 u8 *data, u32 len)
{
	u32 i = 0;

	if (len % 4)
		return;

	for (i = 0; i < len / 4; i++)
		*(u32 *)(data + i * sizeof(u32)) = nbl_mbx_rd32(phy_mgt, reg + i * sizeof(u32));
}

static void nbl_hw_write_mbx_regs(struct nbl_phy_mgt *phy_mgt, u64 reg,
				  u8 *data, u32 len)
{
	u32 i = 0;

	if (len % 4)
		return;

	for (i = 0; i < len / 4; i++)
		nbl_mbx_wr32(phy_mgt, reg + i * sizeof(u32), *(u32 *)(data + i * sizeof(u32)));
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

static void nbl_phy_config_mailbox_rxq(void *priv, u64 dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_rx_table qinfo_cfg_rx_table = { 0 };

	qinfo_cfg_rx_table.rx_queue_rst = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table,
			      sizeof(qinfo_cfg_rx_table));

	qinfo_cfg_rx_table.rx_queue_base_addr_l = NBL_LO_DWORD(dma_addr);
	qinfo_cfg_rx_table.rx_queue_base_addr_h = NBL_HI_DWORD(dma_addr);
	qinfo_cfg_rx_table.rx_queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_rx_table.rx_queue_rst = 0;
	qinfo_cfg_rx_table.rx_queue_en = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table,
			      sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_config_mailbox_txq(void *priv, u64 dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_tx_table qinfo_cfg_tx_table = { 0 };

	qinfo_cfg_tx_table.tx_queue_rst = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table,
			      sizeof(qinfo_cfg_tx_table));

	qinfo_cfg_tx_table.tx_queue_base_addr_l = NBL_LO_DWORD(dma_addr);
	qinfo_cfg_tx_table.tx_queue_base_addr_h = NBL_HI_DWORD(dma_addr);
	qinfo_cfg_tx_table.tx_queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_tx_table.tx_queue_rst = 0;
	qinfo_cfg_tx_table.tx_queue_en = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table,
			      sizeof(qinfo_cfg_tx_table));
}

static void nbl_phy_stop_mailbox_rxq(void *priv)
{
	struct nbl_mailbox_qinfo_cfg_rx_table qinfo_cfg_rx_table = { 0 };

	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table,
			      sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_stop_mailbox_txq(void *priv)
{
	struct nbl_mailbox_qinfo_cfg_tx_table qinfo_cfg_tx_table = { 0 };

	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table,
			      sizeof(qinfo_cfg_tx_table));
}

static u16 nbl_phy_get_mailbox_rx_tail_ptr(void *priv)
{
	struct nbl_mailbox_qinfo_cfg_dbg_tbl cfg_dbg_tbl = { 0 };

	nbl_hw_read_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_DBG_TABLE_ADDR,
			     (u8 *)&cfg_dbg_tbl, sizeof(cfg_dbg_tbl));
	return cfg_dbg_tbl.rx_tail_ptr;
}

static void nbl_phy_update_mailbox_queue_tail_ptr(void *priv, u16 tail_ptr,
						  u8 txrx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = txrx;
	u32 value = ((u32)tail_ptr << NBL_TAIL_PTR_OFT) | local_qid;

	rte_wmb();
	nbl_mbx_wr32(phy_mgt, NBL_MAILBOX_NOTIFY_ADDR, value);
	rte_delay_us(NBL_NOTIFY_DELAY_MIN_TIME_FOR_REGS);
}

static struct nbl_phy_ops phy_ops = {
	.update_tail_ptr		= nbl_phy_update_tail_ptr,
	.get_tail_ptr			= nbl_phy_get_tail_ptr,

	/* mailbox */
	.config_mailbox_rxq		= nbl_phy_config_mailbox_rxq,
	.config_mailbox_txq		= nbl_phy_config_mailbox_txq,
	.stop_mailbox_rxq		= nbl_phy_stop_mailbox_rxq,
	.stop_mailbox_txq		= nbl_phy_stop_mailbox_txq,
	.get_mailbox_rx_tail_ptr	= nbl_phy_get_mailbox_rx_tail_ptr,
	.update_mailbox_queue_tail_ptr	= nbl_phy_update_mailbox_queue_tail_ptr,
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
	const struct rte_pci_device *pci_dev = adapter->pci_dev;
	int ret = 0;

	phy_mgt_leonis_snic = (struct nbl_phy_mgt_leonis_snic **)&NBL_ADAPTER_TO_PHY_MGT(adapter);
	phy_ops_tbl = &NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);

	/* map device */
	ret = nbl_pci_map_device(adapter);
	if (ret)
		return ret;

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
	nbl_pci_unmap_device(adapter);
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
	nbl_pci_unmap_device(adapter);
}
