/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_atomic.h>
#include <ethdev_driver.h>
#include "spnic_compat.h"
#include "spnic_hwdev.h"
#include "spnic_csr.h"
#include "spnic_hwif.h"
#include "spnic_mgmt.h"
#include "spnic_mbox.h"

#define SPNIC_MBOX_INT_DST_FUNC_SHIFT				0
#define SPNIC_MBOX_INT_DST_AEQN_SHIFT				10
#define SPNIC_MBOX_INT_SRC_RESP_AEQN_SHIFT			12
#define SPNIC_MBOX_INT_STAT_DMA_SHIFT				14
/* The size of data to be send (unit of 4 bytes) */
#define SPNIC_MBOX_INT_TX_SIZE_SHIFT				20
/* SO_RO(strong order, relax order) */
#define SPNIC_MBOX_INT_STAT_DMA_SO_RO_SHIFT			25
#define SPNIC_MBOX_INT_WB_EN_SHIFT				28

#define SPNIC_MBOX_INT_DST_AEQN_MASK				0x3
#define SPNIC_MBOX_INT_SRC_RESP_AEQN_MASK			0x3
#define SPNIC_MBOX_INT_STAT_DMA_MASK				0x3F
#define SPNIC_MBOX_INT_TX_SIZE_MASK				0x1F
#define SPNIC_MBOX_INT_STAT_DMA_SO_RO_MASK			0x3
#define SPNIC_MBOX_INT_WB_EN_MASK				0x1

#define SPNIC_MBOX_INT_SET(val, field)	\
			(((val) & SPNIC_MBOX_INT_##field##_MASK) << \
			SPNIC_MBOX_INT_##field##_SHIFT)

enum spnic_mbox_tx_status {
	TX_NOT_DONE = 1,
};

#define SPNIC_MBOX_CTRL_TRIGGER_AEQE_SHIFT			0
/* Specifies the issue request for the message data.
 * 0 - Tx request is done;
 * 1 - Tx request is in process.
 */
#define SPNIC_MBOX_CTRL_TX_STATUS_SHIFT				1
#define SPNIC_MBOX_CTRL_DST_FUNC_SHIFT				16

#define SPNIC_MBOX_CTRL_TRIGGER_AEQE_MASK			0x1
#define SPNIC_MBOX_CTRL_TX_STATUS_MASK				0x1
#define SPNIC_MBOX_CTRL_DST_FUNC_MASK				0x1FFF

#define SPNIC_MBOX_CTRL_SET(val, field)	\
			(((val) & SPNIC_MBOX_CTRL_##field##_MASK) << \
			SPNIC_MBOX_CTRL_##field##_SHIFT)

#define MBOX_SEGLEN_MASK			\
		SPNIC_MSG_HEADER_SET(SPNIC_MSG_HEADER_SEG_LEN_MASK, SEG_LEN)

#define MBOX_MSG_POLLING_TIMEOUT	300000
#define SPNIC_MBOX_COMP_TIME		300000U

#define MBOX_MAX_BUF_SZ			2048UL
#define MBOX_HEADER_SZ			8
#define SPNIC_MBOX_DATA_SIZE		(MBOX_MAX_BUF_SZ - MBOX_HEADER_SZ)

#define MBOX_TLP_HEADER_SZ		16

/* Mbox size is 64B, 8B for mbox_header, 8B reserved */
#define MBOX_SEG_LEN			48
#define MBOX_SEG_LEN_ALIGN		4
#define MBOX_WB_STATUS_LEN		16UL

/* Mbox write back status is 16B, only first 4B is used */
#define MBOX_WB_STATUS_ERRCODE_MASK		0xFFFF
#define MBOX_WB_STATUS_MASK			0xFF
#define MBOX_WB_ERROR_CODE_MASK			0xFF00
#define MBOX_WB_STATUS_FINISHED_SUCCESS		0xFF
#define MBOX_WB_STATUS_FINISHED_WITH_ERR	0xFE
#define MBOX_WB_STATUS_NOT_FINISHED		0x00

#define MBOX_STATUS_FINISHED(wb)	\
	(((wb) & MBOX_WB_STATUS_MASK) != MBOX_WB_STATUS_NOT_FINISHED)
#define MBOX_STATUS_SUCCESS(wb)		\
	(((wb) & MBOX_WB_STATUS_MASK) == MBOX_WB_STATUS_FINISHED_SUCCESS)
#define MBOX_STATUS_ERRCODE(wb)		\
	((wb) & MBOX_WB_ERROR_CODE_MASK)

#define SEQ_ID_START_VAL			0
#define SEQ_ID_MAX_VAL				42

#define DST_AEQ_IDX_DEFAULT_VAL			0
#define SRC_AEQ_IDX_DEFAULT_VAL			0
#define NO_DMA_ATTRIBUTE_VAL			0

#define MBOX_MSG_NO_DATA_LEN			1

#define MBOX_BODY_FROM_HDR(header)	((u8 *)(header) + MBOX_HEADER_SZ)
#define MBOX_AREA(hwif)			\
	((hwif)->cfg_regs_base + SPNIC_FUNC_CSR_MAILBOX_DATA_OFF)

#define IS_PF_OR_PPF_SRC(src_func_idx)	((src_func_idx) < SPNIC_MAX_PF_FUNCS)

#define MBOX_RESPONSE_ERROR		0x1
#define MBOX_MSG_ID_MASK		0xF
#define MBOX_MSG_ID(func_to_func)	((func_to_func)->send_msg_id)
#define MBOX_MSG_ID_INC(func_to_func)	((MBOX_MSG_ID(func_to_func) + 1) & \
					MBOX_MSG_ID_MASK)

/* Max message counter waits to process for one function */
#define SPNIC_MAX_MSG_CNT_TO_PROCESS	10

enum mbox_ordering_type {
	STRONG_ORDER,
};

enum mbox_write_back_type {
	WRITE_BACK = 1,
};

enum mbox_aeq_trig_type {
	NOT_TRIGGER,
	TRIGGER,
};

static int send_mbox_to_func(struct spnic_mbox *func_to_func,
			     enum spnic_mod_type mod, u16 cmd, void *msg,
			     u16 msg_len, u16 dst_func,
			     enum spnic_msg_direction_type direction,
			     enum spnic_msg_ack_type ack_type,
			     struct mbox_msg_info *msg_info);
static int send_tlp_mbox_to_func(struct spnic_mbox *func_to_func,
				 enum spnic_mod_type mod, u16 cmd, void *msg,
				 u16 msg_len, u16 dst_func,
				 enum spnic_msg_direction_type direction,
				 enum spnic_msg_ack_type ack_type,
				 struct mbox_msg_info *msg_info);

static int recv_vf_mbox_handler(struct spnic_mbox *func_to_func,
				struct spnic_recv_mbox *recv_mbox,
				void *buf_out, u16 *out_size,
				__rte_unused void *param)
{
	int err = 0;

	switch (recv_mbox->mod) {
	case SPNIC_MOD_COMM:
		err = vf_handle_pf_comm_mbox(func_to_func->hwdev, func_to_func,
					     recv_mbox->cmd, recv_mbox->mbox,
					     recv_mbox->mbox_len,
					     buf_out, out_size);
		break;
	default:
		PMD_DRV_LOG(ERR, "No handler, mod: %d", recv_mbox->mod);
		err = SPNIC_MBOX_VF_CMD_ERROR;
		break;
	}

	return err;
}

static void response_for_recv_func_mbox(struct spnic_mbox *func_to_func,
					struct spnic_recv_mbox *recv_mbox,
					int err, u16 out_size, u16 src_func_idx)
{
	struct mbox_msg_info msg_info = {0};

	if (recv_mbox->ack_type == SPNIC_MSG_ACK) {
		msg_info.msg_id = recv_mbox->msg_info.msg_id;
		if (err)
			msg_info.status = SPNIC_MBOX_PF_SEND_ERR;

		if (IS_TLP_MBX(src_func_idx))
			send_tlp_mbox_to_func(func_to_func, recv_mbox->mod,
					      recv_mbox->cmd,
					      recv_mbox->buf_out, out_size,
					      src_func_idx, SPNIC_MSG_RESPONSE,
					      SPNIC_MSG_NO_ACK, &msg_info);
		else
			send_mbox_to_func(func_to_func, recv_mbox->mod,
					  recv_mbox->cmd, recv_mbox->buf_out,
					  out_size, src_func_idx,
					  SPNIC_MSG_RESPONSE,
					  SPNIC_MSG_NO_ACK, &msg_info);
	}
}

static void recv_func_mbox_handler(struct spnic_mbox *func_to_func,
				   struct spnic_recv_mbox *recv_mbox,
				   u16 src_func_idx, void *param)
{
	struct spnic_hwdev *hwdev = func_to_func->hwdev;
	void *buf_out = recv_mbox->buf_out;
	u16 out_size = MBOX_MAX_BUF_SZ;
	int err = 0;

	if (SPNIC_IS_VF(hwdev)) {
		err = recv_vf_mbox_handler(func_to_func, recv_mbox, buf_out,
					   &out_size, param);
	} else {
		err = -EINVAL;
		PMD_DRV_LOG(ERR, "PMD doesn't support non-VF handle mailbox message");
	}

	if (!out_size || err)
		out_size = MBOX_MSG_NO_DATA_LEN;

	if (recv_mbox->ack_type == SPNIC_MSG_ACK) {
		response_for_recv_func_mbox(func_to_func, recv_mbox, err,
					    out_size, src_func_idx);
	}
}

static void resp_mbox_handler(struct spnic_mbox *func_to_func,
			      struct spnic_recv_mbox *recv_mbox)
{
	rte_spinlock_lock(&func_to_func->mbox_lock);
	if (recv_mbox->msg_info.msg_id == func_to_func->send_msg_id &&
	    func_to_func->event_flag == EVENT_START)
		func_to_func->event_flag = EVENT_SUCCESS;
	else
		PMD_DRV_LOG(ERR, "Mbox response timeout, current send msg id(0x%x), "
			    "recv msg id(0x%x), status(0x%x)",
			    func_to_func->send_msg_id,
			    recv_mbox->msg_info.msg_id,
			    recv_mbox->msg_info.status);
	rte_spinlock_unlock(&func_to_func->mbox_lock);
}

static bool check_mbox_segment(struct spnic_recv_mbox *recv_mbox,
			       u64 mbox_header)
{
	u8 seq_id, seg_len, msg_id, mod;
	u16 src_func_idx, cmd;

	seq_id = SPNIC_MSG_HEADER_GET(mbox_header, SEQID);
	seg_len = SPNIC_MSG_HEADER_GET(mbox_header, SEG_LEN);
	src_func_idx = SPNIC_MSG_HEADER_GET(mbox_header, SRC_GLB_FUNC_IDX);
	msg_id = SPNIC_MSG_HEADER_GET(mbox_header, MSG_ID);
	mod = SPNIC_MSG_HEADER_GET(mbox_header, MODULE);
	cmd = SPNIC_MSG_HEADER_GET(mbox_header, CMD);

	if (seq_id > SEQ_ID_MAX_VAL || seg_len > MBOX_SEG_LEN)
		goto seg_err;

	if (seq_id == 0) {
		recv_mbox->seq_id = seq_id;
		recv_mbox->msg_info.msg_id = msg_id;
		recv_mbox->mod = mod;
		recv_mbox->cmd = cmd;
	} else {
		if ((seq_id != recv_mbox->seq_id + 1) ||
		    msg_id != recv_mbox->msg_info.msg_id ||
		    mod != recv_mbox->mod || cmd != recv_mbox->cmd)
			goto seg_err;

		recv_mbox->seq_id = seq_id;
	}

	return true;

seg_err:
	PMD_DRV_LOG(ERR, "Mailbox segment check failed, src func id: 0x%x, "
		"front seg info: seq id: 0x%x, msg id: 0x%x, mod: 0x%x, "
		"cmd: 0x%x\n",
		src_func_idx, recv_mbox->seq_id, recv_mbox->msg_info.msg_id,
		recv_mbox->mod, recv_mbox->cmd);
	PMD_DRV_LOG(ERR, "Current seg info: seg len: 0x%x, seq id: 0x%x, "
		"msg id: 0x%x, mod: 0x%x, cmd: 0x%x\n",
		seg_len, seq_id, msg_id, mod, cmd);

	return false;
}

static int recv_mbox_handler(struct spnic_mbox *func_to_func, void *header,
			     struct spnic_recv_mbox *recv_mbox, void *param)
{
	u64 mbox_header = *((u64 *)header);
	void *mbox_body = MBOX_BODY_FROM_HDR(header);
	u16 src_func_idx;
	int pos;
	u8 seq_id;

	seq_id = SPNIC_MSG_HEADER_GET(mbox_header, SEQID);
	src_func_idx = SPNIC_MSG_HEADER_GET(mbox_header, SRC_GLB_FUNC_IDX);

	if (!check_mbox_segment(recv_mbox, mbox_header)) {
		recv_mbox->seq_id = SEQ_ID_MAX_VAL;
		return SPNIC_MSG_HANDLER_RES;
	}

	pos = seq_id * MBOX_SEG_LEN;
	memcpy((u8 *)recv_mbox->mbox + pos, mbox_body,
	       SPNIC_MSG_HEADER_GET(mbox_header, SEG_LEN));

	if (!SPNIC_MSG_HEADER_GET(mbox_header, LAST))
		return SPNIC_MSG_HANDLER_RES;

	recv_mbox->cmd = SPNIC_MSG_HEADER_GET(mbox_header, CMD);
	recv_mbox->mod = SPNIC_MSG_HEADER_GET(mbox_header, MODULE);
	recv_mbox->mbox_len = SPNIC_MSG_HEADER_GET(mbox_header, MSG_LEN);
	recv_mbox->ack_type = SPNIC_MSG_HEADER_GET(mbox_header, NO_ACK);
	recv_mbox->msg_info.msg_id = SPNIC_MSG_HEADER_GET(mbox_header, MSG_ID);
	recv_mbox->msg_info.status = SPNIC_MSG_HEADER_GET(mbox_header, STATUS);
	recv_mbox->seq_id = SEQ_ID_MAX_VAL;

	if (SPNIC_MSG_HEADER_GET(mbox_header, DIRECTION) ==
	    SPNIC_MSG_RESPONSE) {
		resp_mbox_handler(func_to_func, recv_mbox);
		return 0;
	}

	recv_func_mbox_handler(func_to_func, recv_mbox, src_func_idx, param);

	return SPNIC_MSG_HANDLER_RES;
}

int spnic_mbox_func_aeqe_handler(void *handle, u8 *header,
				 __rte_unused u8 size, void *param)
{
	struct spnic_mbox *func_to_func = NULL;
	struct spnic_recv_mbox *recv_mbox = NULL;
	u64 mbox_header = *((u64 *)header);
	u64 src, dir;

	func_to_func = ((struct spnic_hwdev *)handle)->func_to_func;

	dir = SPNIC_MSG_HEADER_GET(mbox_header, DIRECTION);
	src = SPNIC_MSG_HEADER_GET(mbox_header, SRC_GLB_FUNC_IDX);

	if (src >= SPNIC_MAX_FUNCTIONS && src != SPNIC_MGMT_SRC_ID) {
		PMD_DRV_LOG(ERR, "Mailbox source function id: %u is invalid",
			    (u32)src);
		return SPNIC_MSG_HANDLER_RES;
	}

	src = (src == SPNIC_MGMT_SRC_ID) ? SPNIC_MAX_FUNCTIONS : src;

	recv_mbox = (dir == SPNIC_MSG_DIRECT_SEND) ?
		    &func_to_func->mbox_send[src] :
		    &func_to_func->mbox_resp[src];

	return recv_mbox_handler(func_to_func, (u64 *)header, recv_mbox, param);
}

static void clear_mbox_status(struct spnic_send_mbox *mbox)
{
	*mbox->wb_status = 0;

	/* Clear mailbox write back status */
	rte_wmb();
}

static void mbox_copy_header(struct spnic_send_mbox *mbox, u64 *header)
{
	u32 *data = (u32 *)header;
	u32 i, idx_max = MBOX_HEADER_SZ / sizeof(u32);

	for (i = 0; i < idx_max; i++) {
		rte_write32(cpu_to_be32(*(data + i)),
			    mbox->data + i * sizeof(u32));
	}
}

#define MBOX_DMA_MSG_INIT_XOR_VAL	0x5a5a5a5a
static u32 mbox_dma_msg_xor(u32 *data, u16 msg_len)
{
	u32 xor = MBOX_DMA_MSG_INIT_XOR_VAL;
	u16 dw_len = msg_len / sizeof(u32);
	u16 i;

	for (i = 0; i < dw_len; i++)
		xor ^= data[i];

	return xor;
}

static void mbox_copy_send_data_addr(struct spnic_send_mbox *mbox, u16 seg_len)
{
	u32 addr_h, addr_l, xor;

	xor = mbox_dma_msg_xor(mbox->sbuff_vaddr, seg_len);
	addr_h = upper_32_bits(mbox->sbuff_paddr);
	addr_l = lower_32_bits(mbox->sbuff_paddr);

	rte_write32(cpu_to_be32(xor), mbox->data + MBOX_HEADER_SZ);
	rte_write32(cpu_to_be32(addr_h),
		    mbox->data + MBOX_HEADER_SZ + sizeof(u32));
	rte_write32(cpu_to_be32(addr_l),
		     mbox->data + MBOX_HEADER_SZ + 2 * sizeof(u32));
	rte_write32(cpu_to_be32(seg_len),
		     mbox->data + MBOX_HEADER_SZ + 3 * sizeof(u32));
	/* Reserved */
	rte_write32(0, mbox->data + MBOX_HEADER_SZ + 4 * sizeof(u32));
	rte_write32(0, mbox->data + MBOX_HEADER_SZ + 5 * sizeof(u32));
}

static void mbox_copy_send_data(struct spnic_send_mbox *mbox, void *seg,
				u16 seg_len)
{
	u32 *data = seg;
	u32 data_len, chk_sz = sizeof(u32);
	u32 i, idx_max;

	data_len = seg_len;
	idx_max = RTE_ALIGN(data_len, chk_sz) / chk_sz;

	for (i = 0; i < idx_max; i++) {
		rte_write32(cpu_to_be32(*(data + i)),
			    mbox->data + MBOX_HEADER_SZ + i * sizeof(u32));
	}
}

static void write_mbox_msg_attr(struct spnic_mbox *func_to_func,
				u16 dst_func, u16 dst_aeqn, u16 seg_len)
{
	u32 mbox_int, mbox_ctrl;

	/* If VF, function ids must self-learning by HW(PPF=1 PF=0) */
	if (SPNIC_IS_VF(func_to_func->hwdev) &&
	    dst_func != SPNIC_MGMT_SRC_ID) {
		if (dst_func == SPNIC_HWIF_PPF_IDX(func_to_func->hwdev->hwif))
			dst_func = 1;
		else
			dst_func = 0;
	}

	mbox_int = SPNIC_MBOX_INT_SET(dst_aeqn, DST_AEQN) |
		   SPNIC_MBOX_INT_SET(0, SRC_RESP_AEQN) |
		   SPNIC_MBOX_INT_SET(NO_DMA_ATTRIBUTE_VAL, STAT_DMA) |
		   SPNIC_MBOX_INT_SET(RTE_ALIGN(seg_len + MBOX_HEADER_SZ,
						 MBOX_SEG_LEN_ALIGN) >> 2,
				       TX_SIZE) |
		   SPNIC_MBOX_INT_SET(STRONG_ORDER, STAT_DMA_SO_RO) |
		   SPNIC_MBOX_INT_SET(WRITE_BACK, WB_EN);

	spnic_hwif_write_reg(func_to_func->hwdev->hwif,
			      SPNIC_FUNC_CSR_MAILBOX_INT_OFFSET_OFF, mbox_int);

	rte_wmb(); /* Writing the mbox intr attributes */
	mbox_ctrl = SPNIC_MBOX_CTRL_SET(TX_NOT_DONE, TX_STATUS);

	mbox_ctrl |= SPNIC_MBOX_CTRL_SET(NOT_TRIGGER, TRIGGER_AEQE);

	mbox_ctrl |= SPNIC_MBOX_CTRL_SET(dst_func, DST_FUNC);

	spnic_hwif_write_reg(func_to_func->hwdev->hwif,
			      SPNIC_FUNC_CSR_MAILBOX_CONTROL_OFF, mbox_ctrl);
}

static void dump_mbox_reg(struct spnic_hwdev *hwdev)
{
	u32 val;

	val = spnic_hwif_read_reg(hwdev->hwif,
				  SPNIC_FUNC_CSR_MAILBOX_CONTROL_OFF);
	PMD_DRV_LOG(ERR, "Mailbox control reg: 0x%x", val);
	val = spnic_hwif_read_reg(hwdev->hwif,
				  SPNIC_FUNC_CSR_MAILBOX_INT_OFFSET_OFF);
	PMD_DRV_LOG(ERR, "Mailbox interrupt offset: 0x%x", val);
}

static u16 get_mbox_status(struct spnic_send_mbox *mbox)
{
	/* Write back is 16B, but only use first 4B */
	u64 wb_val = be64_to_cpu(*mbox->wb_status);

	rte_rmb(); /* Verify reading before check */

	return (u16)(wb_val & MBOX_WB_STATUS_ERRCODE_MASK);
}

static int send_mbox_seg(struct spnic_mbox *func_to_func, u64 header,
			 u16 dst_func, void *seg, u16 seg_len,
			 __rte_unused void *msg_info)
{
	struct spnic_send_mbox *send_mbox = &func_to_func->send_mbox;
	struct spnic_hwdev *hwdev = func_to_func->hwdev;
	u8 num_aeqs = hwdev->hwif->attr.num_aeqs;
	u16 dst_aeqn, wb_status = 0, errcode;
	u16 seq_dir = SPNIC_MSG_HEADER_GET(header, DIRECTION);
	u32 cnt = 0;

	/* Mbox to mgmt cpu, hardware doesn't care dst aeq id */
	if (num_aeqs >= 2)
		dst_aeqn = (seq_dir == SPNIC_MSG_DIRECT_SEND) ?
			   SPNIC_ASYNC_MSG_AEQ : SPNIC_MBOX_RSP_MSG_AEQ;
	else
		dst_aeqn = 0;

	clear_mbox_status(send_mbox);

	mbox_copy_header(send_mbox, &header);

	mbox_copy_send_data(send_mbox, seg, seg_len);

	write_mbox_msg_attr(func_to_func, dst_func, dst_aeqn, seg_len);

	rte_wmb(); /* Writing the mbox msg attributes */

	while (cnt < MBOX_MSG_POLLING_TIMEOUT) {
		wb_status = get_mbox_status(send_mbox);
		if (MBOX_STATUS_FINISHED(wb_status))
			break;

		rte_delay_ms(1);
		cnt++;
	}

	if (cnt == MBOX_MSG_POLLING_TIMEOUT) {
		PMD_DRV_LOG(ERR, "Send mailbox segment timeout, wb status: 0x%x",
			    wb_status);
		dump_mbox_reg(hwdev);
		return -ETIMEDOUT;
	}

	if (!MBOX_STATUS_SUCCESS(wb_status)) {
		PMD_DRV_LOG(ERR, "Send mailbox segment to function %d error, wb status: 0x%x",
			    dst_func, wb_status);
		errcode = MBOX_STATUS_ERRCODE(wb_status);
		return errcode ? errcode : -EFAULT;
	}

	return 0;
}

static int send_tlp_mbox_seg(struct spnic_mbox *func_to_func, u64 header,
			     u16 dst_func, void *seg, u16 seg_len,
			     __rte_unused void *msg_info)
{
	struct spnic_send_mbox *send_mbox = &func_to_func->send_mbox;
	struct spnic_hwdev *hwdev = func_to_func->hwdev;
	u8 num_aeqs = hwdev->hwif->attr.num_aeqs;
	u16 dst_aeqn, wb_status = 0, errcode;
	u16 seq_dir = SPNIC_MSG_HEADER_GET(header, DIRECTION);
	u32 cnt = 0;

	/* Mbox to mgmt cpu, hardware doesn't care dst aeq id */
	if (num_aeqs >= 2)
		dst_aeqn = (seq_dir == SPNIC_MSG_DIRECT_SEND) ?
			    SPNIC_ASYNC_MSG_AEQ : SPNIC_MBOX_RSP_MSG_AEQ;
	else
		dst_aeqn = 0;

	clear_mbox_status(send_mbox);

	mbox_copy_header(send_mbox, &header);

	/* Copy data to DMA buffer */
	memcpy(send_mbox->sbuff_vaddr, seg, seg_len);

	/* Copy data address to mailbox ctrl csr */
	mbox_copy_send_data_addr(send_mbox, seg_len);

	/* Send tlp mailbox, needs to change the txsize to 16 */
	write_mbox_msg_attr(func_to_func, dst_func, dst_aeqn,
			    MBOX_TLP_HEADER_SZ);

	rte_wmb(); /* Writing the mbox msg attributes */

	while (cnt < MBOX_MSG_POLLING_TIMEOUT) {
		wb_status = get_mbox_status(send_mbox);
		if (MBOX_STATUS_FINISHED(wb_status))
			break;

		rte_delay_ms(1);
		cnt++;
	}

	if (cnt == MBOX_MSG_POLLING_TIMEOUT) {
		PMD_DRV_LOG(ERR, "Send mailbox segment timeout, wb status: 0x%x",
			    wb_status);
		dump_mbox_reg(hwdev);
		return -ETIMEDOUT;
	}

	if (!MBOX_STATUS_SUCCESS(wb_status)) {
		PMD_DRV_LOG(ERR, "Send mailbox segment to function %d error, wb status: 0x%x",
			    dst_func, wb_status);
		errcode = MBOX_STATUS_ERRCODE(wb_status);
		return errcode ? errcode : -EFAULT;
	}

	return 0;
}

static int send_mbox_to_func(struct spnic_mbox *func_to_func,
			     enum spnic_mod_type mod, u16 cmd, void *msg,
			     u16 msg_len, u16 dst_func,
			     enum spnic_msg_direction_type direction,
			     enum spnic_msg_ack_type ack_type,
			     struct mbox_msg_info *msg_info)
{
	int err = 0;
	u32 seq_id = 0;
	u16 seg_len = MBOX_SEG_LEN;
	u16 rsp_aeq_id, left = msg_len;
	u8 *msg_seg = (u8 *)msg;
	u64 header = 0;

	rsp_aeq_id = SPNIC_MBOX_RSP_MSG_AEQ;

	err = spnic_mutex_lock(&func_to_func->msg_send_mutex);
	if (err)
		return err;

	header = SPNIC_MSG_HEADER_SET(msg_len, MSG_LEN) |
		 SPNIC_MSG_HEADER_SET(mod, MODULE) |
		 SPNIC_MSG_HEADER_SET(seg_len, SEG_LEN) |
		 SPNIC_MSG_HEADER_SET(ack_type, NO_ACK) |
		 SPNIC_MSG_HEADER_SET(SPNIC_DATA_INLINE, DATA_TYPE) |
		 SPNIC_MSG_HEADER_SET(SEQ_ID_START_VAL, SEQID) |
		 SPNIC_MSG_HEADER_SET(NOT_LAST_SEGMENT, LAST) |
		 SPNIC_MSG_HEADER_SET(direction, DIRECTION) |
		 SPNIC_MSG_HEADER_SET(cmd, CMD) |
		 /* The VF's offset to it's associated PF */
		 SPNIC_MSG_HEADER_SET(msg_info->msg_id, MSG_ID) |
		 SPNIC_MSG_HEADER_SET(rsp_aeq_id, AEQ_ID) |
		 SPNIC_MSG_HEADER_SET(SPNIC_MSG_FROM_MBOX, SOURCE) |
		 SPNIC_MSG_HEADER_SET(!!msg_info->status, STATUS);

	while (!(SPNIC_MSG_HEADER_GET(header, LAST))) {
		if (left <= MBOX_SEG_LEN) {
			header &= ~MBOX_SEGLEN_MASK;
			header |= SPNIC_MSG_HEADER_SET(left, SEG_LEN);
			header |= SPNIC_MSG_HEADER_SET(LAST_SEGMENT, LAST);

			seg_len = left;
		}

		err = send_mbox_seg(func_to_func, header, dst_func, msg_seg,
				    seg_len, msg_info);
		if (err) {
			PMD_DRV_LOG(ERR, "Send mbox seg failed, seq_id: 0x%x",
				    (u8)SPNIC_MSG_HEADER_GET(header, SEQID));

			goto send_err;
		}

		left -= MBOX_SEG_LEN;
		msg_seg += MBOX_SEG_LEN;

		seq_id++;
		header &= ~(SPNIC_MSG_HEADER_SET(SPNIC_MSG_HEADER_SEQID_MASK,
						  SEQID));
		header |= SPNIC_MSG_HEADER_SET(seq_id, SEQID);
	}

send_err:
	(void)spnic_mutex_unlock(&func_to_func->msg_send_mutex);

	return err;
}

static int send_tlp_mbox_to_func(struct spnic_mbox *func_to_func,
				 enum spnic_mod_type mod, u16 cmd, void *msg,
				 u16 msg_len, u16 dst_func,
				 enum spnic_msg_direction_type direction,
				 enum spnic_msg_ack_type ack_type,
				 struct mbox_msg_info *msg_info)
{
	struct spnic_hwdev *hwdev = func_to_func->hwdev;
	u8 *msg_seg = (u8 *)msg;
	int err = 0;
	u16 rsp_aeq_id;
	u64 header = 0;

	rsp_aeq_id = SPNIC_MBOX_RSP_MSG_AEQ;

	err = spnic_mutex_lock(&func_to_func->msg_send_mutex);
	if (err)
		return err;

	header = SPNIC_MSG_HEADER_SET(MBOX_TLP_HEADER_SZ, MSG_LEN) |
		 SPNIC_MSG_HEADER_SET(MBOX_TLP_HEADER_SZ, SEG_LEN) |
		 SPNIC_MSG_HEADER_SET(mod, MODULE) |
		 SPNIC_MSG_HEADER_SET(LAST_SEGMENT, LAST) |
		 SPNIC_MSG_HEADER_SET(ack_type, NO_ACK) |
		 SPNIC_MSG_HEADER_SET(SPNIC_DATA_DMA, DATA_TYPE) |
		 SPNIC_MSG_HEADER_SET(SEQ_ID_START_VAL, SEQID) |
		 SPNIC_MSG_HEADER_SET(direction, DIRECTION) |
		 SPNIC_MSG_HEADER_SET(cmd, CMD) |
		 SPNIC_MSG_HEADER_SET(msg_info->msg_id, MSG_ID) |
		 SPNIC_MSG_HEADER_SET(rsp_aeq_id, AEQ_ID) |
		 SPNIC_MSG_HEADER_SET(SPNIC_MSG_FROM_MBOX, SOURCE) |
		 SPNIC_MSG_HEADER_SET(!!msg_info->status, STATUS) |
		 SPNIC_MSG_HEADER_SET(spnic_global_func_id(hwdev),
				       SRC_GLB_FUNC_IDX);

	err = send_tlp_mbox_seg(func_to_func, header, dst_func, msg_seg,
				msg_len, msg_info);
	if (err) {
		PMD_DRV_LOG(ERR, "Send mbox seg failed, seq_id: 0x%x",
			    (u8)SPNIC_MSG_HEADER_GET(header, SEQID));
	}

	(void)spnic_mutex_unlock(&func_to_func->msg_send_mutex);

	return err;
}

static void set_mbox_to_func_event(struct spnic_mbox *func_to_func,
				   enum mbox_event_state event_flag)
{
	rte_spinlock_lock(&func_to_func->mbox_lock);
	func_to_func->event_flag = event_flag;
	rte_spinlock_unlock(&func_to_func->mbox_lock);
}

static int spnic_mbox_to_func(struct spnic_mbox *func_to_func,
			      enum spnic_mod_type mod, u16 cmd, u16 dst_func,
			      void *buf_in, u16 in_size, void *buf_out,
			      u16 *out_size, u32 timeout)
{
	/* Use mbox_resp to hole data which responded from other function */
	struct spnic_recv_mbox *mbox_for_resp = NULL;
	struct mbox_msg_info msg_info = {0};
	u16 mbox_rsp_idx;
	int err;

	mbox_rsp_idx = (dst_func == SPNIC_MGMT_SRC_ID) ?
			SPNIC_MAX_FUNCTIONS : dst_func;

	mbox_for_resp = &func_to_func->mbox_resp[mbox_rsp_idx];

	err = spnic_mutex_lock(&func_to_func->mbox_send_mutex);
	if (err)
		return err;

	msg_info.msg_id = MBOX_MSG_ID_INC(func_to_func);
	func_to_func->send_msg_id = msg_info.msg_id;

	set_mbox_to_func_event(func_to_func, EVENT_START);

	if (IS_TLP_MBX(dst_func))
		err = send_tlp_mbox_to_func(func_to_func, mod, cmd, buf_in,
					    in_size, dst_func,
					    SPNIC_MSG_DIRECT_SEND,
					    SPNIC_MSG_ACK, &msg_info);
	else
		err = send_mbox_to_func(func_to_func, mod, cmd, buf_in,
					in_size, dst_func,
					SPNIC_MSG_DIRECT_SEND,
					SPNIC_MSG_ACK, &msg_info);

	if (err) {
		PMD_DRV_LOG(ERR, "Send mailbox failed, msg_id: %d",
			    msg_info.msg_id);
		set_mbox_to_func_event(func_to_func, EVENT_FAIL);
		goto send_err;
	}

	if (mod != mbox_for_resp->mod || cmd != mbox_for_resp->cmd) {
		PMD_DRV_LOG(ERR, "Invalid response mbox message, mod: 0x%x, cmd: 0x%x, expect mod: 0x%x, cmd: 0x%x, timeout0x%x\n",
			    mbox_for_resp->mod, mbox_for_resp->cmd, mod, cmd, timeout);
		err = -EFAULT;
		goto send_err;
	}

	if (mbox_for_resp->msg_info.status) {
		err = mbox_for_resp->msg_info.status;
		goto send_err;
	}

	if (buf_out && out_size) {
		if (*out_size < mbox_for_resp->mbox_len) {
			PMD_DRV_LOG(ERR, "Invalid response mbox message length: %d for "
				    "mod: %d cmd: %d, should less than: %d",
				    mbox_for_resp->mbox_len, mod, cmd,
				    *out_size);
			err = -EFAULT;
			goto send_err;
		}

		if (mbox_for_resp->mbox_len)
			memcpy(buf_out, mbox_for_resp->mbox,
			       mbox_for_resp->mbox_len);

		*out_size = mbox_for_resp->mbox_len;
	}

send_err:
	(void)spnic_mutex_unlock(&func_to_func->mbox_send_mutex);

	return err;
}

static int mbox_func_params_valid(__rte_unused struct spnic_mbox *func_to_func,
				  void *buf_in, u16 in_size)
{
	if (!buf_in || !in_size)
		return -EINVAL;

	if (in_size > SPNIC_MBOX_DATA_SIZE) {
		PMD_DRV_LOG(ERR, "Mbox msg len(%d) exceed limit(%u)",
			    in_size, (u8)SPNIC_MBOX_DATA_SIZE);
		return -EINVAL;
	}

	return 0;
}

static int spnic_mbox_to_func_no_ack(struct spnic_hwdev *hwdev, u16 func_idx,
				     enum spnic_mod_type mod, u16 cmd,
				     void *buf_in, u16 in_size)
{
	struct spnic_mbox *func_to_func = hwdev->func_to_func;
	struct mbox_msg_info msg_info = {0};
	int err;

	err = mbox_func_params_valid(hwdev->func_to_func, buf_in, in_size);
	if (err)
		return err;

	err = spnic_mutex_lock(&func_to_func->mbox_send_mutex);
	if (err)
		return err;

	if (IS_TLP_MBX(func_idx))
		err = send_tlp_mbox_to_func(func_to_func, mod, cmd,
					    buf_in, in_size, func_idx,
					    SPNIC_MSG_DIRECT_SEND,
					    SPNIC_MSG_NO_ACK, &msg_info);
	else
		err = send_mbox_to_func(func_to_func, mod, cmd,
					buf_in, in_size, func_idx,
					SPNIC_MSG_DIRECT_SEND,
					SPNIC_MSG_NO_ACK, &msg_info);
	if (err)
		PMD_DRV_LOG(ERR, "Send mailbox no ack failed");

	(void)spnic_mutex_unlock(&func_to_func->mbox_send_mutex);

	return err;
}

int spnic_send_mbox_to_mgmt(struct spnic_hwdev *hwdev, enum spnic_mod_type mod,
			    u16 cmd, void *buf_in, u16 in_size, void *buf_out,
			    u16 *out_size, u32 timeout)
{
	struct spnic_mbox *func_to_func = hwdev->func_to_func;
	int err;

	err = mbox_func_params_valid(func_to_func, buf_in, in_size);
	if (err)
		return err;

	return spnic_mbox_to_func(func_to_func, mod, cmd, SPNIC_MGMT_SRC_ID,
				  buf_in, in_size, buf_out, out_size, timeout);
}

void spnic_response_mbox_to_mgmt(struct spnic_hwdev *hwdev,
				 enum spnic_mod_type mod, u16 cmd,
				 void *buf_in, u16 in_size, u16 msg_id)
{
	struct mbox_msg_info msg_info;
	u16 dst_func;

	msg_info.msg_id = (u8)msg_id;
	msg_info.status = 0;
	dst_func = SPNIC_MGMT_SRC_ID;

	if (IS_TLP_MBX(dst_func))
		send_tlp_mbox_to_func(hwdev->func_to_func, mod, cmd, buf_in,
				      in_size, SPNIC_MGMT_SRC_ID,
				      SPNIC_MSG_RESPONSE, SPNIC_MSG_NO_ACK,
				      &msg_info);
	else
		send_mbox_to_func(hwdev->func_to_func, mod, cmd, buf_in,
				  in_size, SPNIC_MGMT_SRC_ID,
				  SPNIC_MSG_RESPONSE, SPNIC_MSG_NO_ACK,
				  &msg_info);
}

int spnic_send_mbox_to_mgmt_no_ack(struct spnic_hwdev *hwdev,
				   enum spnic_mod_type mod, u16 cmd,
				   void *buf_in, u16 in_size)
{
	struct spnic_mbox *func_to_func = hwdev->func_to_func;
	int err;

	err = mbox_func_params_valid(func_to_func, buf_in, in_size);
	if (err)
		return err;

	return spnic_mbox_to_func_no_ack(hwdev, SPNIC_MGMT_SRC_ID, mod, cmd,
					 buf_in, in_size);
}

int spnic_mbox_to_pf(struct spnic_hwdev *hwdev, enum spnic_mod_type mod,
		     u16 cmd, void *buf_in, u16 in_size, void *buf_out,
		     u16 *out_size, u32 timeout)
{
	int err;

	if (!hwdev)
		return -EINVAL;

	err = mbox_func_params_valid(hwdev->func_to_func, buf_in, in_size);
	if (err)
		return err;

	if (!SPNIC_IS_VF(hwdev)) {
		PMD_DRV_LOG(ERR, "Params error, func_type: %d",
			    spnic_func_type(hwdev));
		return -EINVAL;
	}

	return spnic_mbox_to_func(hwdev->func_to_func, mod, cmd,
				  spnic_pf_id_of_vf(hwdev), buf_in, in_size,
				  buf_out, out_size, timeout);
}

int spnic_mbox_to_vf(struct spnic_hwdev *hwdev, enum spnic_mod_type mod,
		     u16 vf_id, u16 cmd, void *buf_in, u16 in_size,
		     void *buf_out, u16 *out_size, u32 timeout)
{
	struct spnic_mbox *func_to_func = NULL;
	u16 dst_func_idx;
	int err = 0;

	if (!hwdev)
		return -EINVAL;

	func_to_func = hwdev->func_to_func;
	err = mbox_func_params_valid(func_to_func, buf_in, in_size);
	if (err)
		return err;

	if (SPNIC_IS_VF(hwdev)) {
		PMD_DRV_LOG(ERR, "Params error, func_type: %d",
			    spnic_func_type(hwdev));
		return -EINVAL;
	}

	if (!vf_id) {
		PMD_DRV_LOG(ERR, "VF id: %d error!", vf_id);
		return -EINVAL;
	}

	/*
	 * The sum of vf_offset_to_pf + vf_id is the VF's global function id of
	 * VF in this pf
	 */
	dst_func_idx = spnic_glb_pf_vf_offset(hwdev) + vf_id;

	return spnic_mbox_to_func(func_to_func, mod, cmd, dst_func_idx, buf_in,
				  in_size, buf_out, out_size, timeout);
}

static int init_mbox_info(struct spnic_recv_mbox *mbox_info,
			  int mbox_max_buf_sz)
{
	int err;

	mbox_info->seq_id = SEQ_ID_MAX_VAL;

	mbox_info->mbox = rte_zmalloc("mbox", (size_t)mbox_max_buf_sz, 1);
	if (!mbox_info->mbox)
		return -ENOMEM;

	mbox_info->buf_out = rte_zmalloc("mbox_buf_out",
					 (size_t)mbox_max_buf_sz, 1);
	if (!mbox_info->buf_out) {
		err = -ENOMEM;
		goto alloc_buf_out_err;
	}

	return 0;

alloc_buf_out_err:
	rte_free(mbox_info->mbox);

	return err;
}

static void clean_mbox_info(struct spnic_recv_mbox *mbox_info)
{
	rte_free(mbox_info->buf_out);
	rte_free(mbox_info->mbox);
}

static int alloc_mbox_info(struct spnic_recv_mbox *mbox_info,
			   int mbox_max_buf_sz)
{
	u16 func_idx, i;
	int err;

	for (func_idx = 0; func_idx < SPNIC_MAX_FUNCTIONS + 1; func_idx++) {
		err = init_mbox_info(&mbox_info[func_idx], mbox_max_buf_sz);
		if (err) {
			PMD_DRV_LOG(ERR, "Init mbox info failed");
			goto init_mbox_info_err;
		}
	}

	return 0;

init_mbox_info_err:
	for (i = 0; i < func_idx; i++)
		clean_mbox_info(&mbox_info[i]);

	return err;
}

static void free_mbox_info(struct spnic_recv_mbox *mbox_info)
{
	u16 func_idx;

	for (func_idx = 0; func_idx < SPNIC_MAX_FUNCTIONS + 1; func_idx++)
		clean_mbox_info(&mbox_info[func_idx]);
}

static void prepare_send_mbox(struct spnic_mbox *func_to_func)
{
	struct spnic_send_mbox *send_mbox = &func_to_func->send_mbox;

	send_mbox->data = MBOX_AREA(func_to_func->hwdev->hwif);
}

static int alloc_mbox_wb_status(struct spnic_mbox *func_to_func)
{
	struct spnic_send_mbox *send_mbox = &func_to_func->send_mbox;
	struct spnic_hwdev *hwdev = func_to_func->hwdev;
	u32 addr_h, addr_l;

	send_mbox->wb_mz = rte_eth_dma_zone_reserve(hwdev->eth_dev, "wb_mz", 0,
						    MBOX_WB_STATUS_LEN,
						    RTE_CACHE_LINE_SIZE,
						    SOCKET_ID_ANY);
	if (!send_mbox->wb_mz)
		return -ENOMEM;

	send_mbox->wb_vaddr = send_mbox->wb_mz->addr;
	send_mbox->wb_paddr = send_mbox->wb_mz->iova;
	send_mbox->wb_status = send_mbox->wb_vaddr;

	addr_h = upper_32_bits(send_mbox->wb_paddr);
	addr_l = lower_32_bits(send_mbox->wb_paddr);

	spnic_hwif_write_reg(hwdev->hwif, SPNIC_FUNC_CSR_MAILBOX_RESULT_H_OFF,
			      addr_h);
	spnic_hwif_write_reg(hwdev->hwif, SPNIC_FUNC_CSR_MAILBOX_RESULT_L_OFF,
			      addr_l);

	return 0;
}

static void free_mbox_wb_status(struct spnic_mbox *func_to_func)
{
	struct spnic_send_mbox *send_mbox = &func_to_func->send_mbox;
	struct spnic_hwdev *hwdev = func_to_func->hwdev;

	spnic_hwif_write_reg(hwdev->hwif,
			      SPNIC_FUNC_CSR_MAILBOX_RESULT_H_OFF, 0);
	spnic_hwif_write_reg(hwdev->hwif,
			      SPNIC_FUNC_CSR_MAILBOX_RESULT_L_OFF, 0);

	rte_memzone_free(send_mbox->wb_mz);
}

static int alloc_mbox_tlp_buffer(struct spnic_mbox *func_to_func)
{
	struct spnic_send_mbox *send_mbox = &func_to_func->send_mbox;
	struct spnic_hwdev *hwdev = func_to_func->hwdev;

	send_mbox->sbuff_mz = rte_eth_dma_zone_reserve(hwdev->eth_dev,
						       "sbuff_mz", 0,
						       MBOX_MAX_BUF_SZ,
						       MBOX_MAX_BUF_SZ,
						       SOCKET_ID_ANY);
	if (!send_mbox->sbuff_mz)
		return -ENOMEM;

	send_mbox->sbuff_vaddr = send_mbox->sbuff_mz->addr;
	send_mbox->sbuff_paddr = send_mbox->sbuff_mz->iova;

	return 0;
}

static void free_mbox_tlp_buffer(struct spnic_mbox *func_to_func)
{
	struct spnic_send_mbox *send_mbox = &func_to_func->send_mbox;

	rte_memzone_free(send_mbox->sbuff_mz);
}

int spnic_func_to_func_init(struct spnic_hwdev *hwdev)
{
	struct spnic_mbox *func_to_func;
	int err;

	func_to_func = rte_zmalloc("func_to_func", sizeof(*func_to_func), 1);
	if (!func_to_func)
		return -ENOMEM;

	hwdev->func_to_func = func_to_func;
	func_to_func->hwdev = hwdev;
	(void)spnic_mutex_init(&func_to_func->mbox_send_mutex, NULL);
	(void)spnic_mutex_init(&func_to_func->msg_send_mutex, NULL);
	rte_spinlock_init(&func_to_func->mbox_lock);

	err = alloc_mbox_info(func_to_func->mbox_send, MBOX_MAX_BUF_SZ);
	if (err) {
		PMD_DRV_LOG(ERR, "Alloc mem for mbox_active failed");
		goto alloc_mbox_for_send_err;
	}

	err = alloc_mbox_info(func_to_func->mbox_resp, MBOX_MAX_BUF_SZ);
	if (err) {
		PMD_DRV_LOG(ERR, "Alloc mem for mbox_passive failed");
		goto alloc_mbox_for_resp_err;
	}

	err = alloc_mbox_tlp_buffer(func_to_func);
	if (err) {
		PMD_DRV_LOG(ERR, "Alloc mbox send buffer failed");
		goto alloc_tlp_buffer_err;
	}

	err = alloc_mbox_wb_status(func_to_func);
	if (err) {
		PMD_DRV_LOG(ERR, "Alloc mbox write back status failed");
		goto alloc_wb_status_err;
	}

	prepare_send_mbox(func_to_func);

	return 0;

alloc_wb_status_err:
	free_mbox_tlp_buffer(func_to_func);

alloc_tlp_buffer_err:
	free_mbox_info(func_to_func->mbox_resp);

alloc_mbox_for_resp_err:
	free_mbox_info(func_to_func->mbox_send);

alloc_mbox_for_send_err:
	(void)spnic_mutex_destroy(&func_to_func->msg_send_mutex);
	(void)spnic_mutex_destroy(&func_to_func->mbox_send_mutex);
	rte_free(func_to_func);

	return err;
}

void spnic_func_to_func_free(struct spnic_hwdev *hwdev)
{
	struct spnic_mbox *func_to_func = hwdev->func_to_func;

	free_mbox_wb_status(func_to_func);
	free_mbox_tlp_buffer(func_to_func);
	free_mbox_info(func_to_func->mbox_resp);
	free_mbox_info(func_to_func->mbox_send);
	(void)spnic_mutex_destroy(&func_to_func->mbox_send_mutex);
	(void)spnic_mutex_destroy(&func_to_func->msg_send_mutex);

	rte_free(func_to_func);
}
