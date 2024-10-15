/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <stdint.h>
#include <string.h>

#include <ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "zxdh_ethdev.h"
#include "zxdh_logs.h"
#include "zxdh_msg.h"
#include "zxdh_common.h"

#define ZXDH_MSG_RSP_SIZE_MAX  512

#define ZXDH_COMMON_TABLE_READ   0
#define ZXDH_COMMON_TABLE_WRITE  1

#define ZXDH_COMMON_FIELD_PHYPORT  6
#define ZXDH_COMMON_FIELD_DATACH   3

#define RSC_TBL_CONTENT_LEN_MAX  (257 * 2)

#define REPS_HEADER_PAYLOAD_OFFSET  4
#define TBL_MSG_PRO_SUCCESS  0xaa

struct zxdh_common_msg {
	uint8_t  type;    /* 0:read table 1:write table */
	uint8_t  field;
	uint16_t pcie_id;
	uint16_t slen;    /* Data length for write table */
	uint16_t reserved;
} __rte_packed;

struct zxdh_common_rsp_hdr {
	uint8_t  rsp_status;
	uint16_t rsp_len;
	uint8_t  reserved;
	uint8_t  payload_status;
	uint8_t  rsv;
	uint16_t payload_len;
} __rte_packed;

struct tbl_msg_header {
	uint8_t  type;  /* r/w */
	uint8_t  field;
	uint16_t pcieid;
	uint16_t slen;
	uint16_t rsv;
};
struct tbl_msg_reps_header {
	uint8_t  check;
	uint8_t  rsv;
	uint16_t len;
};

static int32_t zxdh_fill_common_msg(struct zxdh_hw *hw,
	struct zxdh_pci_bar_msg *desc,
	uint8_t        type,
	uint8_t        field,
	void          *buff,
	uint16_t       buff_size)
{
	uint64_t msg_len = sizeof(struct zxdh_common_msg) + buff_size;

	desc->payload_addr = rte_zmalloc(NULL, msg_len, 0);
	if (unlikely(desc->payload_addr == NULL)) {
		PMD_DRV_LOG(ERR, "Failed to allocate msg_data");
		return -ENOMEM;
	}
	memset(desc->payload_addr, 0, msg_len);
	desc->payload_len = msg_len;
	struct zxdh_common_msg *msg_data = (struct zxdh_common_msg *)desc->payload_addr;

	msg_data->type = type;
	msg_data->field = field;
	msg_data->pcie_id = hw->pcie_id;
	msg_data->slen = buff_size;
	if (buff_size != 0)
		rte_memcpy(msg_data + 1, buff, buff_size);

	return 0;
}

static int32_t zxdh_send_command(struct zxdh_hw *hw,
	struct zxdh_pci_bar_msg      *desc,
	enum bar_module_id            module_id,
	struct zxdh_msg_recviver_mem *msg_rsp)
{
	desc->virt_addr = (uint64_t)(hw->bar_addr[ZXDH_BAR0_INDEX] + ZXDH_CTRLCH_OFFSET);
	desc->src = hw->is_pf ? MSG_CHAN_END_PF : MSG_CHAN_END_VF;
	desc->dst = MSG_CHAN_END_RISC;
	desc->module_id = module_id;
	desc->src_pcieid = hw->pcie_id;

	msg_rsp->buffer_len  = ZXDH_MSG_RSP_SIZE_MAX;
	msg_rsp->recv_buffer = rte_zmalloc(NULL, msg_rsp->buffer_len, 0);
	if (unlikely(msg_rsp->recv_buffer == NULL)) {
		PMD_DRV_LOG(ERR, "Failed to allocate messages response");
		return -ENOMEM;
	}

	if (zxdh_bar_chan_sync_msg_send(desc, msg_rsp) != BAR_MSG_OK) {
		PMD_DRV_LOG(ERR, "Failed to send sync messages or receive response");
		rte_free(msg_rsp->recv_buffer);
		return -1;
	}

	return 0;
}

static int32_t zxdh_common_rsp_check(struct zxdh_msg_recviver_mem *msg_rsp,
		void *buff, uint16_t len)
{
	struct zxdh_common_rsp_hdr *rsp_hdr = (struct zxdh_common_rsp_hdr *)msg_rsp->recv_buffer;

	if ((rsp_hdr->payload_status != 0xaa) || (rsp_hdr->payload_len != len)) {
		PMD_DRV_LOG(ERR, "Common response is invalid, status:0x%x rsp_len:%d",
					rsp_hdr->payload_status, rsp_hdr->payload_len);
		return -1;
	}
	if (len != 0)
		rte_memcpy(buff, rsp_hdr + 1, len);

	return 0;
}

static int32_t zxdh_common_table_read(struct zxdh_hw *hw, uint8_t field,
			void *buff, uint16_t buff_size)
{
	struct zxdh_msg_recviver_mem msg_rsp;
	struct zxdh_pci_bar_msg desc;
	int32_t ret = 0;

	if (!hw->msg_chan_init) {
		PMD_DRV_LOG(ERR, "Bar messages channel not initialized");
		return -1;
	}

	ret = zxdh_fill_common_msg(hw, &desc, ZXDH_COMMON_TABLE_READ, field, NULL, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to fill common msg");
		return ret;
	}

	ret = zxdh_send_command(hw, &desc, BAR_MODULE_TBL, &msg_rsp);
	if (ret != 0)
		goto free_msg_data;

	ret = zxdh_common_rsp_check(&msg_rsp, buff, buff_size);
	if (ret != 0)
		goto free_rsp_data;

free_rsp_data:
	rte_free(msg_rsp.recv_buffer);
free_msg_data:
	rte_free(desc.payload_addr);
	return ret;
}

int32_t zxdh_phyport_get(struct rte_eth_dev *dev, uint8_t *phyport)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	int32_t ret = zxdh_common_table_read(hw, ZXDH_COMMON_FIELD_PHYPORT,
					(void *)phyport, sizeof(*phyport));
	return ret;
}

static inline void zxdh_fill_res_para(struct rte_eth_dev *dev, struct zxdh_res_para *param)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	param->pcie_id   = hw->pcie_id;
	param->virt_addr = hw->bar_addr[0] + ZXDH_CTRLCH_OFFSET;
	param->src_type  = BAR_MODULE_TBL;
}

static int zxdh_get_res_info(struct zxdh_res_para *dev, uint8_t field, uint8_t *res, uint16_t *len)
{
	if (!res || !dev)
		return BAR_MSG_ERR_NULL;

	struct tbl_msg_header tbl_msg = {
		.type = TBL_TYPE_READ,
		.field = field,
		.pcieid = dev->pcie_id,
		.slen = 0,
		.rsv = 0,
	};

	struct zxdh_pci_bar_msg in = {0};

	in.virt_addr = dev->virt_addr;
	in.payload_addr = &tbl_msg;
	in.payload_len = sizeof(tbl_msg);
	in.src = dev->src_type;
	in.dst = MSG_CHAN_END_RISC;
	in.module_id = BAR_MODULE_TBL;
	in.src_pcieid = dev->pcie_id;

	uint8_t recv_buf[RSC_TBL_CONTENT_LEN_MAX + 8] = {0};
	struct zxdh_msg_recviver_mem result = {
		.recv_buffer = recv_buf,
		.buffer_len = sizeof(recv_buf),
	};
	int ret = zxdh_bar_chan_sync_msg_send(&in, &result);

	if (ret != BAR_MSG_OK) {
		PMD_DRV_LOG(ERR,
			"send sync_msg failed. pcieid: 0x%x, ret: %d.\n", dev->pcie_id, ret);
		return ret;
	}
	struct tbl_msg_reps_header *tbl_reps =
		(struct tbl_msg_reps_header *)(recv_buf + REPS_HEADER_PAYLOAD_OFFSET);

	if (tbl_reps->check != TBL_MSG_PRO_SUCCESS) {
		PMD_DRV_LOG(ERR,
			"get resource_field failed. pcieid: 0x%x, ret: %d.\n", dev->pcie_id, ret);
		return ret;
	}
	*len = tbl_reps->len;
	memcpy(res,
		(recv_buf + REPS_HEADER_PAYLOAD_OFFSET + sizeof(struct tbl_msg_reps_header)), *len);
	return ret;
}

static int zxdh_get_res_panel_id(struct zxdh_res_para *in, uint8_t *panel_id)
{
	uint8_t reps = 0;
	uint16_t reps_len = 0;

	if (zxdh_get_res_info(in, TBL_FIELD_PNLID, &reps, &reps_len) != BAR_MSG_OK)
		return -1;

	*panel_id = reps;
	return BAR_MSG_OK;
}

int32_t zxdh_pannelid_get(struct rte_eth_dev *dev, uint8_t *pannelid)
{
	struct zxdh_res_para param;

	zxdh_fill_res_para(dev, &param);
	int32_t ret = zxdh_get_res_panel_id(&param, pannelid);
	return ret;
}

uint32_t zxdh_read_bar_reg(struct rte_eth_dev *dev, uint32_t bar, uint32_t reg)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint64_t baseaddr = (uint64_t)(hw->bar_addr[bar]);
	uint32_t val      = *((volatile uint32_t *)(baseaddr + reg));
	return val;
}

void zxdh_write_bar_reg(struct rte_eth_dev *dev, uint32_t bar, uint32_t reg, uint32_t val)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint64_t baseaddr = (uint64_t)(hw->bar_addr[bar]);
	*((volatile uint32_t *)(baseaddr + reg)) = val;
}

int32_t zxdh_acquire_lock(struct zxdh_hw *hw)
{
	uint32_t var = zxdh_read_comm_reg((uint64_t)hw->common_cfg, ZXDH_VF_LOCK_REG);

	/* check whether lock is used */
	if (!(var & ZXDH_VF_LOCK_ENABLE_MASK))
		return -1;

	return 0;
}

int32_t zxdh_release_lock(struct zxdh_hw *hw)
{
	uint32_t var = zxdh_read_comm_reg((uint64_t)hw->common_cfg, ZXDH_VF_LOCK_REG);

	if (var & ZXDH_VF_LOCK_ENABLE_MASK) {
		var &= ~ZXDH_VF_LOCK_ENABLE_MASK;
		zxdh_write_comm_reg((uint64_t)hw->common_cfg, ZXDH_VF_LOCK_REG, var);
		return 0;
	}

	return -1;
}

uint32_t zxdh_read_comm_reg(uint64_t pci_comm_cfg_baseaddr, uint32_t reg)
{
	uint32_t val = *((volatile uint32_t *)(pci_comm_cfg_baseaddr + reg));
	return val;
}

void zxdh_write_comm_reg(uint64_t pci_comm_cfg_baseaddr, uint32_t reg, uint32_t val)
{
	*((volatile uint32_t *)(pci_comm_cfg_baseaddr + reg)) = val;
}

static int32_t zxdh_common_table_write(struct zxdh_hw *hw, uint8_t field,
			void *buff, uint16_t buff_size)
{
	struct zxdh_pci_bar_msg desc;
	struct zxdh_msg_recviver_mem msg_rsp;
	int32_t ret = 0;

	if (!hw->msg_chan_init) {
		PMD_DRV_LOG(ERR, "Bar messages channel not initialized");
		return -1;
	}
	if ((buff_size != 0) && (buff == NULL)) {
		PMD_DRV_LOG(ERR, "Buff is invalid");
		return -1;
	}

	ret = zxdh_fill_common_msg(hw, &desc, ZXDH_COMMON_TABLE_WRITE,
					field, buff, buff_size);

	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to fill common msg");
		return ret;
	}

	ret = zxdh_send_command(hw, &desc, BAR_MODULE_TBL, &msg_rsp);
	if (ret != 0)
		goto free_msg_data;

	ret = zxdh_common_rsp_check(&msg_rsp, NULL, 0);
	if (ret != 0)
		goto free_rsp_data;

free_rsp_data:
	rte_free(msg_rsp.recv_buffer);
free_msg_data:
	rte_free(desc.payload_addr);
	return ret;
}

int32_t zxdh_datach_set(struct rte_eth_dev *dev)
{
	/* payload: queue_num(2byte) + pch1(2byte) + ** + pchn */
	struct zxdh_hw *hw = dev->data->dev_private;
	uint16_t buff_size = (hw->queue_num + 1) * 2;
	void *buff = rte_zmalloc(NULL, buff_size, 0);

	if (unlikely(buff == NULL)) {
		PMD_DRV_LOG(ERR, "Failed to allocate buff");
		return -ENOMEM;
	}
	memset(buff, 0, buff_size);
	uint16_t *pdata = (uint16_t *)buff;
	*pdata++ = hw->queue_num;
	uint16_t i;

	for (i = 0; i < hw->queue_num; i++)
		*(pdata + i) = hw->channel_context[i].ph_chno;

	int32_t ret = zxdh_common_table_write(hw, ZXDH_COMMON_FIELD_DATACH,
						(void *)buff, buff_size);

	if (ret != 0)
		PMD_DRV_LOG(ERR, "Failed to setup data channel of common table");

	rte_free(buff);
	return ret;
}
