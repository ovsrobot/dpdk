/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <ethdev_driver.h>
#include <rte_bus_pci.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "spnic_compat.h"
#include "spnic_csr.h"
#include "spnic_hwdev.h"
#include "spnic_hwif.h"
#include "spnic_wq.h"
#include "spnic_mgmt.h"
#include "spnic_cmdq.h"
#include "spnic_hw_comm.h"
#include "spnic_cmd.h"

#define	SPNIC_MSIX_CNT_LLI_TIMER_SHIFT			0
#define	SPNIC_MSIX_CNT_LLI_CREDIT_SHIFT			8
#define	SPNIC_MSIX_CNT_COALESC_TIMER_SHIFT		8
#define	SPNIC_MSIX_CNT_PENDING_SHIFT			8
#define	SPNIC_MSIX_CNT_RESEND_TIMER_SHIFT		29

#define	SPNIC_MSIX_CNT_LLI_TIMER_MASK			0xFFU
#define	SPNIC_MSIX_CNT_LLI_CREDIT_MASK			0xFFU
#define	SPNIC_MSIX_CNT_COALESC_TIMER_MASK		0xFFU
#define	SPNIC_MSIX_CNT_PENDING_MASK			0x1FU
#define	SPNIC_MSIX_CNT_RESEND_TIMER_MASK		0x7U

#define DEFAULT_RX_BUF_SIZE	((u16)0xB)

enum spnic_rx_buf_size {
	SPNIC_RX_BUF_SIZE_32B = 0x20,
	SPNIC_RX_BUF_SIZE_64B = 0x40,
	SPNIC_RX_BUF_SIZE_96B = 0x60,
	SPNIC_RX_BUF_SIZE_128B = 0x80,
	SPNIC_RX_BUF_SIZE_192B = 0xC0,
	SPNIC_RX_BUF_SIZE_256B = 0x100,
	SPNIC_RX_BUF_SIZE_384B = 0x180,
	SPNIC_RX_BUF_SIZE_512B = 0x200,
	SPNIC_RX_BUF_SIZE_768B = 0x300,
	SPNIC_RX_BUF_SIZE_1K = 0x400,
	SPNIC_RX_BUF_SIZE_1_5K = 0x600,
	SPNIC_RX_BUF_SIZE_2K = 0x800,
	SPNIC_RX_BUF_SIZE_3K = 0xC00,
	SPNIC_RX_BUF_SIZE_4K = 0x1000,
	SPNIC_RX_BUF_SIZE_8K = 0x2000,
	SPNIC_RX_BUF_SIZE_16K = 0x4000,
};

const u32 spnic_hw_rx_buf_size[] = {
	SPNIC_RX_BUF_SIZE_32B,
	SPNIC_RX_BUF_SIZE_64B,
	SPNIC_RX_BUF_SIZE_96B,
	SPNIC_RX_BUF_SIZE_128B,
	SPNIC_RX_BUF_SIZE_192B,
	SPNIC_RX_BUF_SIZE_256B,
	SPNIC_RX_BUF_SIZE_384B,
	SPNIC_RX_BUF_SIZE_512B,
	SPNIC_RX_BUF_SIZE_768B,
	SPNIC_RX_BUF_SIZE_1K,
	SPNIC_RX_BUF_SIZE_1_5K,
	SPNIC_RX_BUF_SIZE_2K,
	SPNIC_RX_BUF_SIZE_3K,
	SPNIC_RX_BUF_SIZE_4K,
	SPNIC_RX_BUF_SIZE_8K,
	SPNIC_RX_BUF_SIZE_16K,
};

int spnic_get_interrupt_cfg(void *dev, struct interrupt_info *info)
{
	struct spnic_hwdev *hwdev = dev;
	struct spnic_cmd_msix_config msix_cfg;
	u16 out_size = sizeof(msix_cfg);
	int err;

	if (!hwdev || !info)
		return -EINVAL;

	memset(&msix_cfg, 0, sizeof(msix_cfg));
	msix_cfg.func_id = spnic_global_func_id(hwdev);
	msix_cfg.msix_index = info->msix_index;
	msix_cfg.opcode = SPNIC_MGMT_CMD_OP_GET;

	err = spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_COMM,
				      MGMT_CMD_CFG_MSIX_CTRL_REG,
				      &msix_cfg, sizeof(msix_cfg),
				      &msix_cfg, &out_size, 0);
	if (err || !out_size || msix_cfg.status) {
		PMD_DRV_LOG(ERR, "Get interrupt config failed, err: %d, "
			    "status: 0x%x, out size: 0x%x",
			    err, msix_cfg.status, out_size);
		return -EINVAL;
	}

	info->lli_credit_limit = msix_cfg.lli_credit_cnt;
	info->lli_timer_cfg = msix_cfg.lli_tmier_cnt;
	info->pending_limt = msix_cfg.pending_cnt;
	info->coalesc_timer_cfg = msix_cfg.coalesct_timer_cnt;
	info->resend_timer_cfg = msix_cfg.resend_timer_cnt;

	return 0;
}

/**
 * Set interrupt cfg
 *
 * @param[in] dev
 *   The pointer to the private hardware device object
 * @param[in] info
 *   Interrupt info
 *
 * @retval zero : Success
 * @retval negative : Failure.
 */
int spnic_set_interrupt_cfg(void *dev, struct interrupt_info info)
{
	struct spnic_hwdev *hwdev = dev;
	struct spnic_cmd_msix_config msix_cfg;
	struct interrupt_info temp_info;
	u16 out_size = sizeof(msix_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	temp_info.msix_index = info.msix_index;
	err = spnic_get_interrupt_cfg(hwdev, &temp_info);
	if (err)
		return -EIO;

	memset(&msix_cfg, 0, sizeof(msix_cfg));
	msix_cfg.func_id = spnic_global_func_id(hwdev);
	msix_cfg.msix_index = (u16)info.msix_index;
	msix_cfg.opcode = SPNIC_MGMT_CMD_OP_SET;

	msix_cfg.lli_credit_cnt = temp_info.lli_credit_limit;
	msix_cfg.lli_tmier_cnt = temp_info.lli_timer_cfg;
	msix_cfg.pending_cnt = temp_info.pending_limt;
	msix_cfg.coalesct_timer_cnt = temp_info.coalesc_timer_cfg;
	msix_cfg.resend_timer_cnt = temp_info.resend_timer_cfg;

	if (info.lli_set) {
		msix_cfg.lli_credit_cnt = info.lli_credit_limit;
		msix_cfg.lli_tmier_cnt = info.lli_timer_cfg;
	}

	if (info.interrupt_coalesc_set) {
		msix_cfg.pending_cnt = info.pending_limt;
		msix_cfg.coalesct_timer_cnt = info.coalesc_timer_cfg;
		msix_cfg.resend_timer_cnt = info.resend_timer_cfg;
	}

	err = spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_COMM,
				     MGMT_CMD_CFG_MSIX_CTRL_REG,
				     &msix_cfg, sizeof(msix_cfg),
				     &msix_cfg, &out_size, 0);
	if (err || !out_size || msix_cfg.status) {
		PMD_DRV_LOG(ERR, "Set interrupt config failed, err: %d, "
			    "status: 0x%x, out size: 0x%x",
			    err, msix_cfg.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_set_wq_page_size(void *hwdev, u16 func_idx, u32 page_size)
{
	struct spnic_cmd_wq_page_size page_size_info;
	u16 out_size = sizeof(page_size_info);
	int err;

	memset(&page_size_info, 0, sizeof(page_size_info));
	page_size_info.func_idx = func_idx;
	page_size_info.page_size = SPNIC_PAGE_SIZE_HW(page_size);
	page_size_info.opcode = SPNIC_MGMT_CMD_OP_SET;

	err = spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_COMM,
				     MGMT_CMD_CFG_PAGESIZE,
				     &page_size_info, sizeof(page_size_info),
				     &page_size_info, &out_size, 0);
	if (err || !out_size || page_size_info.status) {
		PMD_DRV_LOG(ERR, "Set wq page size failed, err: %d, "
			    "status: 0x%x, out_size: 0x%0x",
			    err, page_size_info.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int spnic_set_cmdq_depth(void *hwdev, u16 cmdq_depth)
{
	struct spnic_cmd_root_ctxt root_ctxt;
	u16 out_size = sizeof(root_ctxt);
	int err;

	memset(&root_ctxt, 0, sizeof(root_ctxt));
	root_ctxt.func_idx = spnic_global_func_id(hwdev);
	root_ctxt.set_cmdq_depth = 1;
	root_ctxt.cmdq_depth = (u8)ilog2(cmdq_depth);

	err = spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_COMM, MGMT_CMD_SET_VAT,
				     &root_ctxt, sizeof(root_ctxt),
				     &root_ctxt, &out_size, 0);
	if (err || !out_size || root_ctxt.status) {
		PMD_DRV_LOG(ERR, "Set cmdq depth failed, err: %d, status: 0x%x, out_size: 0x%x",
			    err, root_ctxt.status, out_size);
		return -EFAULT;
	}

	return 0;
}

/**
 * Set the dma attributes for entry
 *
 * @param[in] hwdev
 *   The pointer to the private hardware device object
 * @param[in] entry_idx
 *   The entry index in the dma table
 * @param[in] st
 *   PCIE TLP steering tag
 * @param[in] at
 *   PCIE TLP AT field
 * @param[in] ph
 *   PCIE TLP Processing Hint field
 * @param[in] no_snooping
 *   PCIE TLP No snooping
 * @param[in] tph_en
 *   PCIE TLP Processing Hint Enable
 */
int spnic_set_dma_attr_tbl(struct spnic_hwdev *hwdev, u32 entry_idx, u8 st,
			   u8 at, u8 ph, u8 no_snooping, u8 tph_en)
{
	struct comm_cmd_dma_attr_config dma_attr;
	u16 out_size = sizeof(dma_attr);
	int err;

	memset(&dma_attr, 0, sizeof(dma_attr));
	dma_attr.func_id = spnic_global_func_id(hwdev);
	dma_attr.entry_idx = entry_idx;
	dma_attr.st = st;
	dma_attr.at = at;
	dma_attr.ph = ph;
	dma_attr.no_snooping = no_snooping;
	dma_attr.tph_en = tph_en;

	err = spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_COMM,
				     MGMT_CMD_SET_DMA_ATTR,
				     &dma_attr, sizeof(dma_attr),
				     &dma_attr, &out_size, 0);
	if (err || !out_size || dma_attr.head.status) {
		PMD_DRV_LOG(ERR, "Failed to set dma attr, err: %d, status: 0x%x, out_size: 0x%x\n",
			    err, dma_attr.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}
