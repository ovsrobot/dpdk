/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <ethdev_pci.h>

#include "../sssnic_log.h"
#include "sssnic_hw.h"
#include "sssnic_reg.h"
#include "sssnic_cmd.h"
#include "sssnic_api.h"
#include "sssnic_eventq.h"
#include "sssnic_msg.h"
#include "sssnic_mbox.h"
#include "sssnic_ctrlq.h"

static int
wait_for_sssnic_hw_ready(struct sssnic_hw *hw)
{
	struct sssnic_attr1_reg reg;
	uint32_t timeout_ms = 10;

	do {
		reg.u32 = sssnic_cfg_reg_read(hw, SSSNIC_ATTR1_REG);
		if (reg.u32 != 0xffffffff && reg.mgmt_init_status != 0)
			return 0;
		rte_delay_ms(1);
	} while (--timeout_ms);

	return -EBUSY;
}

static int
wait_for_sssnic_db_enabled(struct sssnic_hw *hw)
{
	struct sssnic_attr4_reg r4;
	struct sssnic_attr5_reg r5;
	uint32_t timeout_ms = 60000;

	do {
		r4.u32 = sssnic_cfg_reg_read(hw, SSSNIC_ATTR4_REG);
		r5.u32 = sssnic_cfg_reg_read(hw, SSSNIC_ATTR5_REG);
		if (r4.db_ctrl == SSSNIC_DB_CTRL_ENABLE &&
			r5.outbound_ctrl == SSSNIC_DB_CTRL_ENABLE)
			return 0;
		rte_delay_ms(1);
	} while (--timeout_ms);

	return -EBUSY;
}

static void
sssnic_attr_setup(struct sssnic_hw *hw)
{
	struct sssnic_attr0_reg attr0;
	struct sssnic_attr1_reg attr1;
	struct sssnic_attr2_reg attr2;
	struct sssnic_attr3_reg attr3;
	struct sssnic_hw_attr *attr = &hw->attr;

	attr0.u32 = sssnic_cfg_reg_read(hw, SSSNIC_ATTR0_REG);
	attr1.u32 = sssnic_cfg_reg_read(hw, SSSNIC_ATTR1_REG);
	attr2.u32 = sssnic_cfg_reg_read(hw, SSSNIC_ATTR2_REG);
	attr3.u32 = sssnic_cfg_reg_read(hw, SSSNIC_ATTR3_REG);

	attr->func_idx = attr0.func_idx;
	attr->pf_idx = attr0.pf_idx;
	attr->pci_idx = attr0.pci_idx;
	attr->vf_off = attr0.vf_off;
	attr->func_type = attr0.func_type;
	attr->af_idx = attr1.af_idx;
	attr->num_aeq = RTE_BIT32(attr1.num_aeq);
	attr->num_ceq = attr2.num_ceq;
	attr->num_irq = attr2.num_irq;
	attr->global_vf_off = attr3.global_vf_off;

	PMD_DRV_LOG(DEBUG, "attr0=0x%x, attr1=0x%x, attr2=0x%x, attr3=0x%x",
		attr0.u32, attr1.u32, attr2.u32, attr3.u32);
}

/* AF and MF election */
static void
sssnic_af_setup(struct sssnic_hw *hw)
{
	struct sssnic_af_election_reg reg0;
	struct sssnic_mf_election_reg reg1;

	/* AF election */
	reg0.u32 = sssnic_mgmt_reg_read(hw, SSSNIC_AF_ELECTION_REG);
	reg0.func_idx = hw->attr.func_idx;
	sssnic_mgmt_reg_write(hw, SSSNIC_AF_ELECTION_REG, reg0.u32);
	reg0.u32 = sssnic_mgmt_reg_read(hw, SSSNIC_AF_ELECTION_REG);
	hw->attr.af_idx = reg0.func_idx;
	if (hw->attr.af_idx == hw->attr.func_idx) {
		hw->attr.func_type = SSSNIC_FUNC_TYPE_AF;
		PMD_DRV_LOG(INFO, "Elected PF %d as AF", hw->attr.func_idx);

		/* MF election */
		reg1.u32 = sssnic_mgmt_reg_read(hw, SSSNIC_MF_ELECTION_REG);
		reg1.func_idx = hw->attr.func_idx;
		sssnic_mgmt_reg_write(hw, SSSNIC_MF_ELECTION_REG, reg1.u32);
		reg1.u32 = sssnic_mgmt_reg_read(hw, SSSNIC_MF_ELECTION_REG);
		hw->attr.mf_idx = reg1.func_idx;
		if (hw->attr.mf_idx == hw->attr.func_idx)
			PMD_DRV_LOG(INFO, "Elected PF %d as MF",
				hw->attr.func_idx);
	}
}

void
sssnic_msix_state_set(struct sssnic_hw *hw, uint16_t msix_id, int state)
{
	struct sssnic_msix_ctrl_reg reg;

	reg.u32 = 0;
	if (state == SSSNIC_MSIX_ENABLE)
		reg.int_msk_clr = 1;
	else
		reg.int_msk_set = 1;
	reg.msxi_idx = msix_id;
	sssnic_cfg_reg_write(hw, SSSNIC_MSIX_CTRL_REG, reg.u32);
}

static void
sssnic_msix_all_disable(struct sssnic_hw *hw)
{
	uint16_t i;
	int num_irqs = hw->attr.num_irq;

	for (i = 0; i < num_irqs; i++)
		sssnic_msix_state_set(hw, i, SSSNIC_MSIX_DISABLE);
}

static void
sssnic_pf_status_set(struct sssnic_hw *hw, enum sssnic_pf_status status)
{
	struct sssnic_attr6_reg reg;

	reg.u32 = sssnic_cfg_reg_read(hw, SSSNIC_ATTR6_REG);
	reg.pf_status = status;
	sssnic_cfg_reg_write(hw, SSSNIC_ATTR6_REG, reg.u32);
}

static int
sssnic_dma_attr_init(struct sssnic_hw *hw)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_dma_attr_set_cmd cmd;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.func_id = SSSNIC_FUNC_IDX(hw);
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_SET_DMA_ATTR_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}
	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SET_DMA_ATTR_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

static int
sssnic_func_reset(struct sssnic_hw *hw)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_func_reset_cmd cmd;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.func_id = SSSNIC_FUNC_IDX(hw);
	cmd.res_mask = RTE_BIT64(0) | RTE_BIT64(1) | RTE_BIT64(2) |
		       RTE_BIT64(10) | RTE_BIT64(12) | RTE_BIT64(13);
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_RESET_FUNC_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}
	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to RESET_FUNC_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

static int
sssnic_pagesize_set(struct sssnic_hw *hw, uint32_t pagesize)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_pagesize_cmd cmd;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.func_id = SSSNIC_FUNC_IDX(hw);
	cmd.pagesz = (uint8_t)rte_log2_u32(pagesize >> 12);
	cmd.opcode = SSSNIC_CMD_OPCODE_SET;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_PAGESIZE_CFG_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}
	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to PAGESIZE_CFG_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

/* Only initialize msix 0 attributes */
static int
sssnic_msix_attr_init(struct sssnic_hw *hw)
{
	int ret;
	struct sssnic_msix_attr attr;

	attr.lli_set = 0;
	attr.coalescing_set = 1;
	attr.pending_limit = 0;
	attr.coalescing_timer = 0xff;
	attr.resend_timer = 0x7;

	ret = sssnic_msix_attr_set(hw, 0, &attr);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set msix0 attributes.");
		return ret;
	}

	return 0;
}

static int
sssnic_capability_init(struct sssnic_hw *hw)
{
	struct sssnic_capability cap;
	int ret;

	ret = sssnic_capability_get(hw, &cap);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get sssnic capability");
		return ret;
	}

	PMD_DRV_LOG(INFO,
		"Initialized capability, physic port:%u, max %u txqs, max %u rxqs",
		cap.phy_port, cap.max_num_txq, cap.max_num_rxq);

	hw->phy_port = cap.phy_port;
	hw->max_num_rxq = cap.max_num_rxq;
	hw->max_num_txq = cap.max_num_txq;

	return 0;
}

static int
sssnic_base_init(struct sssnic_hw *hw)
{
	int ret;
	struct rte_pci_device *pci_dev;

	PMD_INIT_FUNC_TRACE();

	pci_dev = hw->pci_dev;

	/* get base addresses of hw registers */
	hw->cfg_base_addr =
		(uint8_t *)pci_dev->mem_resource[SSSNIC_PCI_BAR_CFG].addr;
	hw->mgmt_base_addr =
		(uint8_t *)pci_dev->mem_resource[SSSNIC_PCI_BAR_MGMT].addr;
	hw->db_base_addr =
		(uint8_t *)pci_dev->mem_resource[SSSNIC_PCI_BAR_DB].addr;
	hw->db_mem_len =
		(uint8_t *)pci_dev->mem_resource[SSSNIC_PCI_BAR_DB].len;

	ret = wait_for_sssnic_hw_ready(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Hardware is not ready!");
		return -EBUSY;
	}
	sssnic_attr_setup(hw);
	ret = wait_for_sssnic_db_enabled(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Doorbell is not enabled!");
		return -EBUSY;
	}
	sssnic_af_setup(hw);
	sssnic_msix_all_disable(hw);
	sssnic_pf_status_set(hw, SSSNIC_PF_STATUS_INIT);

	PMD_DRV_LOG(DEBUG,
		"func_idx:%d, func_type:%d, pci_idx:%d, vf_off:%d, global_vf_off:%d "
		"pf_idx:%d, af_idx:%d, mf_idx:%d, num_aeq:%d, num_ceq:%d, num_irq:%d",
		hw->attr.func_idx, hw->attr.func_type, hw->attr.pci_idx,
		hw->attr.vf_off, hw->attr.global_vf_off, hw->attr.pf_idx,
		hw->attr.af_idx, hw->attr.mf_idx, hw->attr.num_aeq,
		hw->attr.num_ceq, hw->attr.num_irq);

	return 0;
}

int
sssnic_hw_init(struct sssnic_hw *hw)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = sssnic_base_init(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize hardware base");
		return ret;
	}

	ret = sssnic_msg_inbox_init(hw);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to initialize message inbox.");
		return ret;
	}

	ret = sssnic_eventq_all_init(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize event queues");
		goto eventq_init_fail;
	}

	ret = sssnic_mbox_init(hw);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to initialize mailbox");
		goto mbox_init_fail;
	}

	ret = sssnic_func_reset(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to reset function resources");
		goto mbox_init_fail;
	}

	ret = sssnic_dma_attr_init(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize DMA attributes");
		goto mbox_init_fail;
	}

	ret = sssnic_msix_attr_init(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize msix attributes");
		goto mbox_init_fail;
	}

	ret = sssnic_pagesize_set(hw, 0x100000);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set page size to 0x100000");
		goto mbox_init_fail;
	}

	ret = sssnic_ctrlq_init(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize control queue");
		goto ctrlq_init_fail;
	}

	ret = sssnic_capability_init(hw);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize capability");
		goto capbility_init_fail;
	}

	sssnic_pf_status_set(hw, SSSNIC_PF_STATUS_ACTIVE);

	return 0;

capbility_init_fail:
	sssnic_ctrlq_shutdown(hw);
ctrlq_init_fail:
	sssnic_mbox_shutdown(hw);
mbox_init_fail:
	sssnic_eventq_all_shutdown(hw);
eventq_init_fail:
	sssnic_msg_inbox_shutdown(hw);
	return ret;
}

void
sssnic_hw_shutdown(struct sssnic_hw *hw)
{
	PMD_INIT_FUNC_TRACE();

	sssnic_pf_status_set(hw, SSSNIC_PF_STATUS_INIT);
	sssnic_ctrlq_shutdown(hw);
	sssnic_mbox_shutdown(hw);
	sssnic_eventq_all_shutdown(hw);
	sssnic_msg_inbox_shutdown(hw);
}
