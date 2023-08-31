/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_bus_pci.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <ethdev_pci.h>
#include <ethdev_driver.h>

#include "../sssnic_log.h"
#include "sssnic_hw.h"
#include "sssnic_reg.h"
#include "sssnic_misc.h"
#include "sssnic_eventq.h"
#include "sssnic_mbox.h"

#define SSSNIC_MBOX_SEND_RESULT_SIZE 16
#define SSSNIC_MBOX_SEND_BUF_SIZE 2048UL
#define SSSNIC_MBOX_RESP_MSG_EVENTQ 1
#define SSSNIC_MBOX_SEND_DONE_TIMEOUT 500000 /* uint is 10us */
#define SSSNIC_MBOX_DEF_REQ_TIMEOUT 4000 /* millisecond */
#define SSSNIC_MBOX_REQ_ID_MASK 0xf /* request id only 4 bits*/

struct sssnic_sendbox {
	struct sssnic_mbox *mbox;
	/* Send data memory */
	uint8_t *data;
	/* Send result DMA memory zone */
	const struct rte_memzone *result_mz;
	/* Send result DMA virtual address */
	volatile uint64_t *result_addr;
	/* DMA buffer mz */
	const struct rte_memzone *buf_mz;
	/* DMA buffer virtual address */
	uint8_t *buf_addr;
	pthread_mutex_t lock;
};

struct sssnic_mbox_msg_dma_desc {
	/* 32bit xor checksum for DMA data */
	uint32_t checksum;
	/* dword of high DMA address */
	uint32_t dma_addr_hi;
	/* dword of low DMA address */
	uint32_t dma_addr_lo;
	/* DMA data length */
	uint32_t len;
	uint32_t resvd[2];
};
#define SSSNIC_MBOX_MSG_DMA_DESC_SIZE 16

struct sssnic_mbox_send_result {
	union {
		uint16_t u16;
		struct {
			/* SSSNIC_MBOX_SEND_STATUS_xx */
			uint16_t status : 8;
			uint16_t errcode : 8;
		};
	};
};

#define SSSNIC_MBOX_SEND_STATUS_DONE 0xff
#define SSSNIC_MBOX_SEND_STATUS_ERR 0xfe
#define SSSNIC_MBOX_SEND_ERR_NONE 0x0

static inline uint16_t
sssnic_sendbox_result_get(struct sssnic_sendbox *sendbox)
{
	uint64_t result = rte_be_to_cpu_64(rte_read64(sendbox->result_addr));
	return (uint16_t)(result & 0xffff);
}

static inline void
sssnic_sendbox_result_clear(struct sssnic_sendbox *sendbox)
{
	rte_write64(0, sendbox->result_addr);
}

/* Wait send status to done */
static int
sssnic_sendbox_result_wait(struct sssnic_sendbox *sendbox, uint32_t timeout)
{
	int ret;
	struct sssnic_mbox_send_result result;

	do {
		result.u16 = sssnic_sendbox_result_get(sendbox);
		if (result.status == SSSNIC_MBOX_SEND_STATUS_DONE) {
			return 0;
		} else if (result.status == SSSNIC_MBOX_SEND_STATUS_ERR) {
			PMD_DRV_LOG(ERR,
				"Failed to send mbox segment data, error code=%u",
				result.errcode);
			ret = -EFAULT;
			goto err_return;
		}
		if (timeout == 0)
			break;
		rte_delay_us(10);
	} while (--timeout);

	PMD_DRV_LOG(ERR, "Mbox segment data sent time out");
	ret = -ETIMEDOUT;

err_return:
	PMD_DRV_LOG(ERR, "MBOX_SEND_CTRL0_REG=0x%x, SEND_CTRL1_REG=0x%x",
		sssnic_cfg_reg_read(sendbox->mbox->hw,
			SSSNIC_MBOX_SEND_CTRL0_REG),
		sssnic_cfg_reg_read(sendbox->mbox->hw,
			SSSNIC_MBOX_SEND_CTRL1_REG));

	return ret;
}

static void
sssnic_mbox_send_ctrl_set(struct sssnic_mbox *mbox, uint16_t func,
	uint16_t dst_eq, uint16_t len)
{
	struct sssnic_mbox_send_ctrl0_reg ctrl_0;
	struct sssnic_mbox_send_ctrl1_reg ctrl_1;

	ctrl_1.u32 = 0;
	ctrl_1.dma_attr = 0;
	ctrl_1.ordering = 0;
	ctrl_1.dst_eq = dst_eq;
	ctrl_1.src_eq = 0;
	ctrl_1.tx_size = RTE_ALIGN(len + SSSNIC_MSG_HDR_SIZE, 4) >> 2;
	ctrl_1.wb = 1;
	sssnic_cfg_reg_write(mbox->hw, SSSNIC_MBOX_SEND_CTRL1_REG, ctrl_1.u32);
	rte_wmb();

	if (SSSNIC_FUNC_TYPE(mbox->hw) == SSSNIC_FUNC_TYPE_VF &&
		func != SSSNIC_MPU_FUNC_IDX) {
		if (func == SSSNIC_AF_FUNC_IDX(mbox->hw))
			func = 1;
		else
			func = 0;
	}

	ctrl_0.u32 = 0;
	ctrl_0.func = func;
	ctrl_0.src_eq_en = 0;
	ctrl_0.tx_status = SSSNIC_REG_MBOX_TX_READY;
	sssnic_cfg_reg_write(mbox->hw, SSSNIC_MBOX_SEND_CTRL0_REG, ctrl_0.u32);
}

static void
sssnic_mbox_state_set(struct sssnic_mbox *mbox, enum sssnic_mbox_state state)
{
	rte_spinlock_lock(&mbox->state_lock);
	mbox->state = state;
	rte_spinlock_unlock(&mbox->state_lock);
}

static void
sssnic_sendbox_write(struct sssnic_sendbox *sendbox, uint16_t offset,
	uint8_t *data, uint16_t data_len)
{
	uint32_t *send_addr;
	uint32_t send_data;
	uint8_t remain_data[4] = { 0 };
	uint16_t remain;
	uint16_t i;
	uint16_t len;
	uint16_t num_dw;

	len = data_len;
	remain = len & 0x3;
	if (remain > 0) {
		len = len - remain;
		for (i = 0; i < remain; i++)
			remain_data[i] = data[len + i];
	}
	num_dw = len / sizeof(uint32_t);
	send_addr = (uint32_t *)(sendbox->data + offset);

	SSSNIC_DEBUG("data_buf=%p, data_len=%u, aligned_len=%u, remain=%u, "
		     "num_dw=%u send_addr=%p",
		data, data_len, len, remain, num_dw, send_addr);

	for (i = 0; i < num_dw; i++) {
		send_data = *(((uint32_t *)data) + i);
		rte_write32(rte_cpu_to_be_32(send_data), send_addr + i);
	}
	if (remain > 0) {
		send_data = *((uint32_t *)remain_data);
		rte_write32(rte_cpu_to_be_32(send_data), send_addr + i);
	}
}

static inline void
sssnic_mbox_msg_hdr_init(struct sssnic_msg_hdr *msghdr, struct sssnic_msg *msg)
{
	msghdr->u64 = 0;
	if (msg == NULL)
		return;
	if (msg->func == SSSNIC_MPU_FUNC_IDX) {
		msghdr->trans_mode = SSSNIC_MSG_TRANS_MODE_DMA;
		msghdr->length = SSSNIC_MBOX_MSG_DMA_DESC_SIZE;
		msghdr->seg_len = SSSNIC_MBOX_MSG_DMA_DESC_SIZE;
		msghdr->last_seg = 1;
	} else {
		msghdr->trans_mode = SSSNIC_MSG_TRANS_MODE_INLINE;
		msghdr->length = msg->data_len;
		if (msg->data_len > SSSNIC_MSG_MAX_SEG_SIZE) {
			msghdr->seg_len = SSSNIC_MSG_MAX_SEG_SIZE;
			msghdr->last_seg = 0;
		} else {
			msghdr->seg_len = msg->data_len;
			msghdr->last_seg = 1;
		}
	}
	msghdr->module = msg->module;
	msghdr->no_response = !msg->ack;
	msghdr->seg_id = SSSNIC_MSG_MIN_SGE_ID;
	msghdr->type = msg->type;
	msghdr->command = msg->command;
	msghdr->id = msg->id;
	msghdr->eventq = SSSNIC_MBOX_RESP_MSG_EVENTQ;
	msghdr->channel = SSSNIC_MSG_CHAN_MBOX;
	msghdr->status = msg->status;
}

/* Calculate data checksum with XOR */
static uint32_t
sssnic_mbox_dma_data_csum(uint32_t *data, uint16_t data_len)
{
	uint32_t xor = 0x5a5a5a5a;
	uint16_t dw = data_len / sizeof(uint32_t);
	uint16_t i;

	for (i = 0; i < dw; i++)
		xor ^= data[i];
	return xor;
}

static int
sssnic_mbox_dma_send(struct sssnic_mbox *mbox, struct sssnic_msg *msg)
{
	int ret;
	struct sssnic_mbox_msg_dma_desc dma_desc = { 0 };
	struct sssnic_msg_hdr msghdr;
	struct sssnic_sendbox *sendbox = mbox->sendbox;

	/* Init DMA description */
	dma_desc.checksum = sssnic_mbox_dma_data_csum((uint32_t *)msg->data_buf,
		msg->data_len);
	dma_desc.dma_addr_hi = (uint32_t)((sendbox->buf_mz->iova >> 16) >> 16);
	dma_desc.dma_addr_lo = (uint32_t)(sendbox->buf_mz->iova);
	dma_desc.len = msg->data_len;
	/* Copy message data to DMA buffer */
	rte_memcpy(sendbox->buf_addr, msg->data_buf, msg->data_len);
	/* Init message header */
	sssnic_mbox_msg_hdr_init(&msghdr, msg);
	msghdr.function = SSSNIC_FUNC_IDX(mbox->hw);
	/* Clear send result */
	sssnic_sendbox_result_clear(sendbox);
	/* write mbox message header */
	sssnic_sendbox_write(sendbox, 0, (uint8_t *)&msghdr,
		SSSNIC_MSG_HDR_SIZE);
	/* write DMA description*/
	sssnic_sendbox_write(sendbox, SSSNIC_MSG_HDR_SIZE, (void *)&dma_desc,
		sizeof(struct sssnic_mbox_msg_dma_desc));
	/* mbox send control set */
	sssnic_mbox_send_ctrl_set(mbox, msg->func,
		msg->type == SSSNIC_MSG_TYPE_REQ ? 0 :
							 SSSNIC_MBOX_RESP_MSG_EVENTQ,
		SSSNIC_MBOX_MSG_DMA_DESC_SIZE);

	rte_wmb();
	/* Wait for send status becomes done */
	ret = sssnic_sendbox_result_wait(sendbox,
		SSSNIC_MBOX_SEND_DONE_TIMEOUT);
	if (ret != 0)
		PMD_DRV_LOG(ERR, "Failed to send mbox DMA data");

	return ret;
}

static int
sssnic_mbox_inline_send(struct sssnic_mbox *mbox, struct sssnic_msg *msg)
{
	int ret;
	uint16_t remain;
	uint16_t send;
	struct sssnic_msg_hdr msghdr;
	struct sssnic_sendbox *sendbox = mbox->sendbox;

	/* Init message header */
	sssnic_mbox_msg_hdr_init(&msghdr, msg);
	send = 0;
	remain = msg->data_len;
	do {
		/* Clear send result */
		sssnic_sendbox_result_clear(sendbox);
		/* write mbox message header */
		sssnic_sendbox_write(sendbox, 0, (uint8_t *)&msghdr,
			SSSNIC_MSG_HDR_SIZE);
		/* write mbox message data */
		sssnic_sendbox_write(sendbox, SSSNIC_MSG_HDR_SIZE,
			msg->data_buf + send, msghdr.seg_len);
		/* mbox send control set */
		sssnic_mbox_send_ctrl_set(mbox, msg->func,
			msg->type == SSSNIC_MSG_TYPE_REQ ?
				      0 :
				      SSSNIC_MBOX_RESP_MSG_EVENTQ,
			msghdr.seg_len);

		rte_wmb();
		/* Wait for send status becomes done */
		ret = sssnic_sendbox_result_wait(sendbox,
			SSSNIC_MBOX_SEND_DONE_TIMEOUT);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to send mbox inline data");
			return ret;
		}
		/*last segment has been sent*/
		if (msghdr.last_seg)
			break;

		remain -= SSSNIC_MSG_MAX_SEG_SIZE;
		send += SSSNIC_MSG_MAX_SEG_SIZE;
		if (remain <= SSSNIC_MSG_MAX_SEG_SIZE) {
			msghdr.seg_len = remain;
			msghdr.last_seg = 1;
		}
		msghdr.seg_id++;
	} while (remain > 0);

	return 0;
}

static int
sssnic_sendbox_init(struct sssnic_mbox *mbox)
{
	int ret;
	struct sssnic_sendbox *sendbox;
	struct sssnic_hw *hw;
	char m_name[RTE_MEMZONE_NAMESIZE];

	PMD_INIT_FUNC_TRACE();

	hw = mbox->hw;

	sendbox = rte_zmalloc(NULL, sizeof(struct sssnic_sendbox), 1);
	if (sendbox == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memory for sendbox");
		return -ENOMEM;
	}

	hw = mbox->hw;
	mbox->sendbox = sendbox;
	sendbox->mbox = mbox;

	snprintf(m_name, sizeof(m_name), "sssnic%u_mbox_send_result",
		SSSNIC_ETH_PORT_ID(hw));
	sendbox->result_mz = rte_memzone_reserve_aligned(m_name,
		SSSNIC_MBOX_SEND_RESULT_SIZE, SOCKET_ID_ANY,
		RTE_MEMZONE_IOVA_CONTIG, RTE_CACHE_LINE_SIZE);
	if (sendbox->result_mz == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memzone for %s", m_name);
		ret = -ENOMEM;
		goto alloc_send_result_fail;
	}
	sssnic_cfg_reg_write(hw, SSSNIC_MBOX_SEND_RESULT_ADDR_H_REG,
		SSSNIC_UPPER_32_BITS(sendbox->result_mz->iova));
	sssnic_cfg_reg_write(hw, SSSNIC_MBOX_SEND_RESULT_ADDR_L_REG,
		SSSNIC_LOWER_32_BITS(sendbox->result_mz->iova));
	sendbox->result_addr = sendbox->result_mz->addr;

	snprintf(m_name, sizeof(m_name), "sssnic%u_mbox_sendbuf",
		SSSNIC_ETH_PORT_ID(hw));
	sendbox->buf_mz = rte_memzone_reserve_aligned(m_name,
		SSSNIC_MBOX_SEND_BUF_SIZE, SOCKET_ID_ANY,
		RTE_MEMZONE_IOVA_CONTIG, SSSNIC_MBOX_SEND_BUF_SIZE);
	if (sendbox->buf_mz == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memzone for %s", m_name);
		ret = -ENOMEM;
		goto alloc_send_buf_fail;
	};
	sendbox->buf_addr = sendbox->buf_mz->addr;

	sendbox->data = hw->cfg_base_addr + SSSNIC_MBOX_SEND_DATA_BASE_REG;

	pthread_mutex_init(&sendbox->lock, NULL);

	return 0;

alloc_send_buf_fail:
	rte_memzone_free(sendbox->result_mz);
alloc_send_result_fail:
	rte_free(sendbox);
	return ret;
}

static void
sssnic_sendbox_shutdown(struct sssnic_mbox *mbox)
{
	struct sssnic_sendbox *sendbox = mbox->sendbox;

	PMD_INIT_FUNC_TRACE();

	rte_memzone_free(sendbox->buf_mz);
	sssnic_cfg_reg_write(mbox->hw, SSSNIC_MBOX_SEND_RESULT_ADDR_H_REG, 0);
	sssnic_cfg_reg_write(mbox->hw, SSSNIC_MBOX_SEND_RESULT_ADDR_L_REG, 0);
	rte_memzone_free(sendbox->result_mz);
	pthread_mutex_destroy(&sendbox->lock);
	rte_free(sendbox);
}

static int
sssnic_mbox_response_handle(struct sssnic_msg *msg,
	__rte_unused enum sssnic_msg_chann_id chan_id, void *priv)
{
	int ret;
	struct sssnic_mbox *mbox = priv;
	;

	rte_spinlock_lock(&mbox->state_lock);
	if (msg->id == mbox->req_id &&
		mbox->state == SSSNIC_MBOX_STATE_RUNNING) {
		mbox->state = SSSNIC_MBOX_STATE_READY;
		ret = SSSNIC_MSG_DONE;
	} else {
		PMD_DRV_LOG(ERR,
			"Failed to handle mbox response message, msg_id=%u, "
			"req_id=%u, msg_status=%u, mbox_state=%u",
			msg->id, mbox->req_id, msg->status, mbox->state);
		ret = SSSNIC_MSG_REJECT;
	}
	rte_spinlock_unlock(&mbox->state_lock);

	return ret;
}

static int
sssnic_mbox_msg_tx(struct sssnic_mbox *mbox, struct sssnic_msg *msg)
{
	int ret;

	if (mbox == NULL || msg == NULL || msg->data_buf == NULL ||
		msg->data_len == 0 ||
		msg->data_len > SSSNIC_MSG_MAX_DATA_SIZE) {
		PMD_DRV_LOG(ERR, "Bad parameter for mbox message tx");
		return -EINVAL;
	}

	SSSNIC_DEBUG("command=%u, func=%u module=%u, type=%u, ack=%u, seq=%u, "
		     "status=%u, id=%u data_buf=%p, data_len=%u",
		msg->command, msg->func, msg->module, msg->type, msg->ack,
		msg->seg, msg->status, msg->id, msg->data_buf, msg->data_len);

	pthread_mutex_lock(&mbox->sendbox->lock);
	if (msg->func == SSSNIC_MPU_FUNC_IDX)
		ret = sssnic_mbox_dma_send(mbox, msg);
	else
		ret = sssnic_mbox_inline_send(mbox, msg);
	pthread_mutex_unlock(&mbox->sendbox->lock);

	return ret;
}

static int
sssnic_mbox_send_internal(struct sssnic_mbox *mbox, struct sssnic_msg *msg,
	uint8_t *resp_data, uint32_t *resp_data_len, uint32_t timeout_ms)
{
	int ret;
	struct sssnic_msg *resp_msg = NULL;

	if (resp_data != NULL) {
		/* the function of request message equls to response message */
		resp_msg = SSSNIC_MSG_LOCATE(mbox->hw, SSSNIC_MSG_CHAN_MBOX,
			SSSNIC_MSG_TYPE_RESP, SSSNIC_MSG_SRC(msg->func));
		mbox->req_id++;
		mbox->req_id &= SSSNIC_MBOX_REQ_ID_MASK;
		msg->id = mbox->req_id;
		msg->ack = 1;
		sssnic_mbox_state_set(mbox, SSSNIC_MBOX_STATE_RUNNING);
	}
	ret = sssnic_mbox_msg_tx(mbox, msg);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to transmit mbox message, ret=%d",
			ret);
		if (resp_data != NULL)
			sssnic_mbox_state_set(mbox, SSSNIC_MBOX_STATE_FAILED);
		return ret;
	}

	if (resp_data == NULL)
		return 0;

	ret = sssnic_eventq_flush(mbox->hw, SSSNIC_MBOX_RESP_MSG_EVENTQ,
		timeout_ms ? timeout_ms : SSSNIC_MBOX_DEF_REQ_TIMEOUT);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "No response message, ret=%d", ret);
		sssnic_mbox_state_set(mbox, SSSNIC_MBOX_STATE_TIMEOUT);
		return ret;
	}
	if (resp_msg->module != msg->module ||
		resp_msg->command != msg->command) {
		PMD_DRV_LOG(ERR,
			"Received invalid response message, module=%x, command=%x, expected message module=%x, command=%x",
			resp_msg->module, resp_msg->command, msg->module,
			msg->command);
		sssnic_mbox_state_set(mbox, SSSNIC_MBOX_STATE_FAILED);
		return ret;
	}
	sssnic_mbox_state_set(mbox, SSSNIC_MBOX_STATE_READY);

	if (resp_msg->status != 0) {
		PMD_DRV_LOG(ERR, "Bad response status");
		return -EFAULT;
	}

	if (*resp_data_len < resp_msg->data_len) {
		PMD_DRV_LOG(ERR,
			"Invalid response data size %u, expected less than %u for module %x command %x",
			resp_msg->data_len, *resp_data_len, msg->module,
			msg->command);
		return -EFAULT;
	}

	rte_memcpy(resp_data, resp_msg->data_buf, resp_msg->data_len);
	*resp_data_len = resp_msg->data_len;
	return 0;
}

int
sssnic_mbox_send(struct sssnic_hw *hw, struct sssnic_msg *msg,
	uint8_t *resp_data, uint32_t *resp_data_len, uint32_t timeout_ms)
{
	int ret;
	struct sssnic_mbox *mbox;

	if (hw == NULL || msg == NULL ||
		(resp_data != NULL && resp_data_len == NULL)) {
		PMD_DRV_LOG(ERR, "Bad parameter for mbox request");
		return -EINVAL;
	}

	mbox = hw->mbox;

	if (resp_data != NULL) {
		ret = pthread_mutex_lock(&mbox->req_lock);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to lock mbox request lock");
			return ret;
		}
	}
	ret = sssnic_mbox_send_internal(mbox, msg, resp_data, resp_data_len,
		timeout_ms);

	if (resp_data != NULL)
		pthread_mutex_unlock(&mbox->req_lock);

	return ret;
}

int
sssnic_mbox_init(struct sssnic_hw *hw)
{
	int ret;
	struct sssnic_mbox *mbox;

	PMD_INIT_FUNC_TRACE();

	mbox = rte_zmalloc(NULL, sizeof(struct sssnic_mbox), 1);
	if (mbox == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memory for mailbox struct");
		return -ENOMEM;
	}

	pthread_mutex_init(&mbox->req_lock, NULL);
	rte_spinlock_init(&mbox->state_lock);

	mbox->hw = hw;
	hw->mbox = mbox;
	ret = sssnic_sendbox_init(mbox);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize sendbox!");
		goto sendbox_init_fail;
	}

	sssnic_msg_rx_handler_register(hw, SSSNIC_MSG_CHAN_MBOX,
		SSSNIC_MSG_TYPE_RESP, sssnic_mbox_response_handle, mbox);

	return 0;

sendbox_init_fail:
	pthread_mutex_destroy(&mbox->req_lock);
	rte_free(mbox);
	return ret;
}

void
sssnic_mbox_shutdown(struct sssnic_hw *hw)
{
	struct sssnic_mbox *mbox = hw->mbox;

	PMD_INIT_FUNC_TRACE();

	if (mbox == NULL)
		return;

	sssnic_sendbox_shutdown(mbox);
	pthread_mutex_destroy(&mbox->req_lock);
	rte_free(mbox);
}
