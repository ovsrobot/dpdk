/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include <stdbool.h>

#include <rte_common.h>
#include <rte_memcpy.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "zxdh_ethdev.h"
#include "zxdh_logs.h"
#include "zxdh_msg.h"

#define ZXDH_REPS_INFO_FLAG_USABLE  0x00
#define ZXDH_REPS_INFO_FLAG_USED    0xa0

#define ZXDH_BAR_SEQID_NUM_MAX      256

#define ZXDH_PCIEID_IS_PF_MASK      (0x0800)
#define ZXDH_PCIEID_PF_IDX_MASK     (0x0700)
#define ZXDH_PCIEID_VF_IDX_MASK     (0x00ff)
#define ZXDH_PCIEID_EP_IDX_MASK     (0x7000)
/* PCIEID bit field offset */
#define ZXDH_PCIEID_PF_IDX_OFFSET   (8)
#define ZXDH_PCIEID_EP_IDX_OFFSET   (12)

#define ZXDH_MULTIPLY_BY_8(x)       ((x) << 3)
#define ZXDH_MULTIPLY_BY_32(x)      ((x) << 5)
#define ZXDH_MULTIPLY_BY_256(x)     ((x) << 8)

#define ZXDH_MAX_EP_NUM              (4)
#define ZXDH_MAX_HARD_SPINLOCK_NUM   (511)

#define LOCK_PRIMARY_ID_MASK         (0x8000)
/* bar offset */
#define ZXDH_BAR0_CHAN_RISC_OFFSET        (0x2000)
#define ZXDH_BAR0_CHAN_PFVF_OFFSET        (0x3000)
#define ZXDH_BAR0_SPINLOCK_OFFSET         (0x4000)
#define ZXDH_FW_SHRD_OFFSET               (0x5000)
#define ZXDH_FW_SHRD_INNER_HW_LABEL_PAT   (0x800)
#define ZXDH_HW_LABEL_OFFSET   \
	(ZXDH_FW_SHRD_OFFSET + ZXDH_FW_SHRD_INNER_HW_LABEL_PAT)

#define ZXDH_CHAN_RISC_SPINLOCK_OFFSET \
	(ZXDH_BAR0_SPINLOCK_OFFSET - ZXDH_BAR0_CHAN_RISC_OFFSET)
#define ZXDH_CHAN_PFVF_SPINLOCK_OFFSET \
	(ZXDH_BAR0_SPINLOCK_OFFSET - ZXDH_BAR0_CHAN_PFVF_OFFSET)
#define ZXDH_CHAN_RISC_LABEL_OFFSET    \
	(ZXDH_HW_LABEL_OFFSET - ZXDH_BAR0_CHAN_RISC_OFFSET)
#define ZXDH_CHAN_PFVF_LABEL_OFFSET    \
	(ZXDH_HW_LABEL_OFFSET - ZXDH_BAR0_CHAN_PFVF_OFFSET)

#define ZXDH_REPS_HEADER_LEN_OFFSET      1
#define ZXDH_REPS_HEADER_PAYLOAD_OFFSET  4
#define ZXDH_REPS_HEADER_REPLYED         0xff

#define ZXDH_BAR_MSG_CHAN_USABLE  0
#define ZXDH_BAR_MSG_CHAN_USED    1

#define ZXDH_BAR_MSG_POL_MASK     (0x10)
#define ZXDH_BAR_MSG_POL_OFFSET   (4)

#define ZXDH_BAR_ALIGN_WORD_MASK   0xfffffffc
#define ZXDH_BAR_MSG_VALID_MASK    1
#define ZXDH_BAR_MSG_VALID_OFFSET  0

#define ZXDH_BAR_PF_NUM             7
#define ZXDH_BAR_VF_NUM             256
#define ZXDH_BAR_INDEX_PF_TO_VF     0
#define ZXDH_BAR_INDEX_MPF_TO_MPF   0xff
#define ZXDH_BAR_INDEX_MPF_TO_PFVF  0
#define ZXDH_BAR_INDEX_PFVF_TO_MPF  0

#define ZXDH_MAX_HARD_SPINLOCK_ASK_TIMES  (1000)
#define ZXDH_SPINLOCK_POLLING_SPAN_US     (100)

#define ZXDH_BAR_MSG_SRC_NUM   3
#define ZXDH_BAR_MSG_SRC_MPF   0
#define ZXDH_BAR_MSG_SRC_PF    1
#define ZXDH_BAR_MSG_SRC_VF    2
#define ZXDH_BAR_MSG_SRC_ERR   0xff
#define ZXDH_BAR_MSG_DST_NUM   3
#define ZXDH_BAR_MSG_DST_RISC  0
#define ZXDH_BAR_MSG_DST_MPF   2
#define ZXDH_BAR_MSG_DST_PFVF  1
#define ZXDH_BAR_MSG_DST_ERR   0xff

#define ZXDH_LOCK_TYPE_HARD    (1)
#define ZXDH_LOCK_TYPE_SOFT    (0)
#define ZXDH_BAR_INDEX_TO_RISC  0

#define ZXDH_BAR_CHAN_INDEX_SEND  0
#define ZXDH_BAR_CHAN_INDEX_RECV  1

uint8_t subchan_id_tbl[ZXDH_BAR_MSG_SRC_NUM][ZXDH_BAR_MSG_DST_NUM] = {
	{ZXDH_BAR_CHAN_INDEX_SEND, ZXDH_BAR_CHAN_INDEX_SEND, ZXDH_BAR_CHAN_INDEX_SEND},
	{ZXDH_BAR_CHAN_INDEX_SEND, ZXDH_BAR_CHAN_INDEX_SEND, ZXDH_BAR_CHAN_INDEX_RECV},
	{ZXDH_BAR_CHAN_INDEX_SEND, ZXDH_BAR_CHAN_INDEX_RECV, ZXDH_BAR_CHAN_INDEX_RECV}
};

uint8_t chan_id_tbl[ZXDH_BAR_MSG_SRC_NUM][ZXDH_BAR_MSG_DST_NUM] = {
	{ZXDH_BAR_INDEX_TO_RISC, ZXDH_BAR_INDEX_MPF_TO_PFVF, ZXDH_BAR_INDEX_MPF_TO_MPF},
	{ZXDH_BAR_INDEX_TO_RISC, ZXDH_BAR_INDEX_PF_TO_VF,   ZXDH_BAR_INDEX_PFVF_TO_MPF},
	{ZXDH_BAR_INDEX_TO_RISC, ZXDH_BAR_INDEX_PF_TO_VF,   ZXDH_BAR_INDEX_PFVF_TO_MPF}
};

uint8_t lock_type_tbl[ZXDH_BAR_MSG_SRC_NUM][ZXDH_BAR_MSG_DST_NUM] = {
	{ZXDH_LOCK_TYPE_HARD, ZXDH_LOCK_TYPE_HARD, ZXDH_LOCK_TYPE_HARD},
	{ZXDH_LOCK_TYPE_SOFT, ZXDH_LOCK_TYPE_SOFT, ZXDH_LOCK_TYPE_HARD},
	{ZXDH_LOCK_TYPE_HARD, ZXDH_LOCK_TYPE_HARD, ZXDH_LOCK_TYPE_HARD}
};

struct dev_stat {
	uint8_t is_mpf_scanned;
	uint8_t is_res_init;
	int16_t dev_cnt; /* probe cnt */
};
struct dev_stat g_dev_stat = {0};

struct seqid_item {
	void *reps_addr;
	uint16_t id;
	uint16_t buffer_len;
	uint16_t flag;
};

struct seqid_ring {
	uint16_t cur_id;
	rte_spinlock_t lock;
	struct seqid_item reps_info_tbl[ZXDH_BAR_SEQID_NUM_MAX];
};
struct seqid_ring g_seqid_ring = {0};

static uint16_t pcie_id_to_hard_lock(uint16_t src_pcieid, uint8_t dst)
{
	uint16_t lock_id = 0;
	uint16_t pf_idx = (src_pcieid & ZXDH_PCIEID_PF_IDX_MASK) >> ZXDH_PCIEID_PF_IDX_OFFSET;
	uint16_t ep_idx = (src_pcieid & ZXDH_PCIEID_EP_IDX_MASK) >> ZXDH_PCIEID_EP_IDX_OFFSET;

	switch (dst) {
	/* msg to risc */
	case ZXDH_MSG_CHAN_END_RISC:
		lock_id = ZXDH_MULTIPLY_BY_8(ep_idx) + pf_idx;
		break;
	/* msg to pf/vf */
	case ZXDH_MSG_CHAN_END_VF:
	case ZXDH_MSG_CHAN_END_PF:
		lock_id = ZXDH_MULTIPLY_BY_8(ep_idx) + pf_idx +
				ZXDH_MULTIPLY_BY_8(1 + ZXDH_MAX_EP_NUM);
		break;
	default:
		lock_id = 0;
		break;
	}
	if (lock_id >= ZXDH_MAX_HARD_SPINLOCK_NUM)
		lock_id = 0;

	return lock_id;
}

static void label_write(uint64_t label_lock_addr, uint32_t lock_id, uint16_t value)
{
	*(volatile uint16_t *)(label_lock_addr + lock_id * 2) = value;
}

static void spinlock_write(uint64_t virt_lock_addr, uint32_t lock_id, uint8_t data)
{
	*(volatile uint8_t *)((uint64_t)virt_lock_addr + (uint64_t)lock_id) = data;
}

static uint8_t spinlock_read(uint64_t virt_lock_addr, uint32_t lock_id)
{
	return *(volatile uint8_t *)((uint64_t)virt_lock_addr + (uint64_t)lock_id);
}

static int32_t zxdh_spinlock_unlock(uint32_t virt_lock_id, uint64_t virt_addr, uint64_t label_addr)
{
	label_write((uint64_t)label_addr, virt_lock_id, 0);
	spinlock_write(virt_addr, virt_lock_id, 0);
	return 0;
}

static int32_t zxdh_spinlock_lock(uint32_t virt_lock_id, uint64_t virt_addr,
					uint64_t label_addr, uint16_t primary_id)
{
	uint32_t lock_rd_cnt = 0;

	do {
		/* read to lock */
		uint8_t spl_val = spinlock_read(virt_addr, virt_lock_id);

		if (spl_val == 0) {
			label_write((uint64_t)label_addr, virt_lock_id, primary_id);
			break;
		}
		rte_delay_us_block(ZXDH_SPINLOCK_POLLING_SPAN_US);
		lock_rd_cnt++;
	} while (lock_rd_cnt < ZXDH_MAX_HARD_SPINLOCK_ASK_TIMES);
	if (lock_rd_cnt >= ZXDH_MAX_HARD_SPINLOCK_ASK_TIMES)
		return -1;

	return 0;
}

/**
 * Fun: PF init hard_spinlock addr
 */
static int bar_chan_pf_init_spinlock(uint16_t pcie_id, uint64_t bar_base_addr)
{
	int lock_id = pcie_id_to_hard_lock(pcie_id, ZXDH_MSG_CHAN_END_RISC);

	zxdh_spinlock_unlock(lock_id, bar_base_addr + ZXDH_BAR0_SPINLOCK_OFFSET,
			bar_base_addr + ZXDH_HW_LABEL_OFFSET);
	lock_id = pcie_id_to_hard_lock(pcie_id, ZXDH_MSG_CHAN_END_VF);
	zxdh_spinlock_unlock(lock_id, bar_base_addr + ZXDH_BAR0_SPINLOCK_OFFSET,
			bar_base_addr + ZXDH_HW_LABEL_OFFSET);
	return 0;
}

static rte_spinlock_t chan_lock;
int zxdh_msg_chan_init(void)
{
	uint16_t seq_id = 0;

	g_dev_stat.dev_cnt++;
	if (g_dev_stat.is_res_init)
		return ZXDH_BAR_MSG_OK;

	rte_spinlock_init(&chan_lock);
	g_seqid_ring.cur_id = 0;
	rte_spinlock_init(&g_seqid_ring.lock);

	for (seq_id = 0; seq_id < ZXDH_BAR_SEQID_NUM_MAX; seq_id++) {
		struct seqid_item *reps_info = &g_seqid_ring.reps_info_tbl[seq_id];

		reps_info->id = seq_id;
		reps_info->flag = ZXDH_REPS_INFO_FLAG_USABLE;
	}
	g_dev_stat.is_res_init = true;
	return ZXDH_BAR_MSG_OK;
}

int zxdh_bar_msg_chan_exit(void)
{
	if (!g_dev_stat.is_res_init || (--g_dev_stat.dev_cnt > 0))
		return ZXDH_BAR_MSG_OK;

	g_dev_stat.is_res_init = false;
	return ZXDH_BAR_MSG_OK;
}

static int zxdh_bar_chan_msgid_allocate(uint16_t *msgid)
{
	struct seqid_item *seqid_reps_info = NULL;

	rte_spinlock_lock(&g_seqid_ring.lock);
	uint16_t g_id = g_seqid_ring.cur_id;
	uint16_t count = 0;
	int rc = 0;

	do {
		count++;
		++g_id;
		g_id %= ZXDH_BAR_SEQID_NUM_MAX;
		seqid_reps_info = &g_seqid_ring.reps_info_tbl[g_id];
	} while ((seqid_reps_info->flag != ZXDH_REPS_INFO_FLAG_USABLE) &&
		(count < ZXDH_BAR_SEQID_NUM_MAX));

	if (count >= ZXDH_BAR_SEQID_NUM_MAX) {
		rc = -1;
		goto out;
	}
	seqid_reps_info->flag = ZXDH_REPS_INFO_FLAG_USED;
	g_seqid_ring.cur_id = g_id;
	*msgid = g_id;
	rc = ZXDH_BAR_MSG_OK;

out:
	rte_spinlock_unlock(&g_seqid_ring.lock);
	return rc;
}

static uint16_t zxdh_bar_chan_save_recv_info(struct zxdh_msg_recviver_mem *result, uint16_t *msg_id)
{
	int ret = zxdh_bar_chan_msgid_allocate(msg_id);

	if (ret != ZXDH_BAR_MSG_OK)
		return ZXDH_BAR_MSG_ERR_MSGID;

	PMD_MSG_LOG(DEBUG, "allocate msg_id: %u", *msg_id);
	struct seqid_item *reps_info = &g_seqid_ring.reps_info_tbl[*msg_id];

	reps_info->reps_addr = result->recv_buffer;
	reps_info->buffer_len = result->buffer_len;
	return ZXDH_BAR_MSG_OK;
}

static uint8_t zxdh_bar_msg_src_index_trans(uint8_t src)
{
	uint8_t src_index = 0;

	switch (src) {
	case ZXDH_MSG_CHAN_END_MPF:
		src_index = ZXDH_BAR_MSG_SRC_MPF;
		break;
	case ZXDH_MSG_CHAN_END_PF:
		src_index = ZXDH_BAR_MSG_SRC_PF;
		break;
	case ZXDH_MSG_CHAN_END_VF:
		src_index = ZXDH_BAR_MSG_SRC_VF;
		break;
	default:
		src_index = ZXDH_BAR_MSG_SRC_ERR;
		break;
	}
	return src_index;
}

static uint8_t zxdh_bar_msg_dst_index_trans(uint8_t dst)
{
	uint8_t dst_index = 0;

	switch (dst) {
	case ZXDH_MSG_CHAN_END_MPF:
		dst_index = ZXDH_BAR_MSG_DST_MPF;
		break;
	case ZXDH_MSG_CHAN_END_PF:
		dst_index = ZXDH_BAR_MSG_DST_PFVF;
		break;
	case ZXDH_MSG_CHAN_END_VF:
		dst_index = ZXDH_BAR_MSG_DST_PFVF;
		break;
	case ZXDH_MSG_CHAN_END_RISC:
		dst_index = ZXDH_BAR_MSG_DST_RISC;
		break;
	default:
		dst_index = ZXDH_BAR_MSG_SRC_ERR;
		break;
	}
	return dst_index;
}

static int zxdh_bar_chan_send_para_check(struct zxdh_pci_bar_msg *in,
					struct zxdh_msg_recviver_mem *result)
{
	uint8_t src_index = 0;
	uint8_t dst_index = 0;

	if (in == NULL || result == NULL) {
		PMD_MSG_LOG(ERR, "send para ERR: null para.");
		return ZXDH_BAR_MSG_ERR_NULL_PARA;
	}
	src_index = zxdh_bar_msg_src_index_trans(in->src);
	dst_index = zxdh_bar_msg_dst_index_trans(in->dst);

	if (src_index == ZXDH_BAR_MSG_SRC_ERR || dst_index == ZXDH_BAR_MSG_DST_ERR) {
		PMD_MSG_LOG(ERR, "send para ERR: chan doesn't exist.");
		return ZXDH_BAR_MSG_ERR_TYPE;
	}
	if (in->module_id >= ZXDH_BAR_MSG_MODULE_NUM) {
		PMD_MSG_LOG(ERR, "send para ERR: invalid module_id: %d.", in->module_id);
		return ZXDH_BAR_MSG_ERR_MODULE;
	}
	if (in->payload_addr == NULL) {
		PMD_MSG_LOG(ERR, "send para ERR: null message.");
		return ZXDH_BAR_MSG_ERR_BODY_NULL;
	}
	if (in->payload_len > ZXDH_BAR_MSG_PAYLOAD_MAX_LEN) {
		PMD_MSG_LOG(ERR, "send para ERR: len %d is too long.", in->payload_len);
		return ZXDH_BAR_MSG_ERR_LEN;
	}
	if (in->virt_addr == 0 || result->recv_buffer == NULL) {
		PMD_MSG_LOG(ERR, "send para ERR: virt_addr or recv_buffer is NULL.");
		return ZXDH_BAR_MSG_ERR_VIRTADDR_NULL;
	}
	if (result->buffer_len < ZXDH_REPS_HEADER_PAYLOAD_OFFSET)
		PMD_MSG_LOG(ERR, "recv buffer len is short than minimal 4 bytes");

	return ZXDH_BAR_MSG_OK;
}

static uint64_t zxdh_subchan_addr_cal(uint64_t virt_addr, uint8_t chan_id, uint8_t subchan_id)
{
	return virt_addr + (2 * chan_id + subchan_id) * ZXDH_BAR_MSG_ADDR_CHAN_INTERVAL;
}

static uint16_t zxdh_bar_chan_subchan_addr_get(struct zxdh_pci_bar_msg *in, uint64_t *subchan_addr)
{
	uint8_t src_index = zxdh_bar_msg_src_index_trans(in->src);
	uint8_t dst_index = zxdh_bar_msg_dst_index_trans(in->dst);
	uint16_t chan_id = chan_id_tbl[src_index][dst_index];
	uint16_t subchan_id = subchan_id_tbl[src_index][dst_index];

	*subchan_addr = zxdh_subchan_addr_cal(in->virt_addr, chan_id, subchan_id);
	return ZXDH_BAR_MSG_OK;
}

static int zxdh_bar_hard_lock(uint16_t src_pcieid, uint8_t dst, uint64_t virt_addr)
{
	int ret = 0;
	uint16_t lockid = pcie_id_to_hard_lock(src_pcieid, dst);

	PMD_MSG_LOG(DEBUG, "dev pcieid: 0x%x lock, get hardlockid: %u", src_pcieid, lockid);
	if (dst == ZXDH_MSG_CHAN_END_RISC)
		ret = zxdh_spinlock_lock(lockid, virt_addr + ZXDH_CHAN_RISC_SPINLOCK_OFFSET,
					virt_addr + ZXDH_CHAN_RISC_LABEL_OFFSET,
					src_pcieid | LOCK_PRIMARY_ID_MASK);
	else
		ret = zxdh_spinlock_lock(lockid, virt_addr + ZXDH_CHAN_PFVF_SPINLOCK_OFFSET,
					virt_addr + ZXDH_CHAN_PFVF_LABEL_OFFSET,
					src_pcieid | LOCK_PRIMARY_ID_MASK);

	return ret;
}

static void zxdh_bar_hard_unlock(uint16_t src_pcieid, uint8_t dst, uint64_t virt_addr)
{
	uint16_t lockid = pcie_id_to_hard_lock(src_pcieid, dst);

	PMD_MSG_LOG(DEBUG, "dev pcieid: 0x%x unlock, get hardlockid: %u", src_pcieid, lockid);
	if (dst == ZXDH_MSG_CHAN_END_RISC)
		zxdh_spinlock_unlock(lockid, virt_addr + ZXDH_CHAN_RISC_SPINLOCK_OFFSET,
				virt_addr + ZXDH_CHAN_RISC_LABEL_OFFSET);
	else
		zxdh_spinlock_unlock(lockid, virt_addr + ZXDH_CHAN_PFVF_SPINLOCK_OFFSET,
				virt_addr + ZXDH_CHAN_PFVF_LABEL_OFFSET);
}

static int zxdh_bar_chan_lock(uint8_t src, uint8_t dst, uint16_t src_pcieid, uint64_t virt_addr)
{
	int ret = 0;
	uint8_t src_index = zxdh_bar_msg_src_index_trans(src);
	uint8_t dst_index = zxdh_bar_msg_dst_index_trans(dst);

	if (src_index == ZXDH_BAR_MSG_SRC_ERR || dst_index == ZXDH_BAR_MSG_DST_ERR) {
		PMD_MSG_LOG(ERR, "lock ERR: chan doesn't exist.");
		return ZXDH_BAR_MSG_ERR_TYPE;
	}

	ret = zxdh_bar_hard_lock(src_pcieid, dst, virt_addr);
	if (ret != 0)
		PMD_MSG_LOG(ERR, "dev: 0x%x failed to lock.", src_pcieid);

	return ret;
}

static int zxdh_bar_chan_unlock(uint8_t src, uint8_t dst, uint16_t src_pcieid, uint64_t virt_addr)
{
	uint8_t src_index = zxdh_bar_msg_src_index_trans(src);
	uint8_t dst_index = zxdh_bar_msg_dst_index_trans(dst);

	if (src_index == ZXDH_BAR_MSG_SRC_ERR || dst_index == ZXDH_BAR_MSG_DST_ERR) {
		PMD_MSG_LOG(ERR, "unlock ERR: chan doesn't exist.");
		return ZXDH_BAR_MSG_ERR_TYPE;
	}

	zxdh_bar_hard_unlock(src_pcieid, dst, virt_addr);

	return ZXDH_BAR_MSG_OK;
}

static void zxdh_bar_chan_msgid_free(uint16_t msg_id)
{
	struct seqid_item *seqid_reps_info = &g_seqid_ring.reps_info_tbl[msg_id];

	rte_spinlock_lock(&g_seqid_ring.lock);
	seqid_reps_info->flag = ZXDH_REPS_INFO_FLAG_USABLE;
	PMD_MSG_LOG(DEBUG, "free msg_id: %u", msg_id);
	rte_spinlock_unlock(&g_seqid_ring.lock);
}

static int zxdh_bar_chan_reg_write(uint64_t subchan_addr, uint32_t offset, uint32_t data)
{
	uint32_t algin_offset = (offset & ZXDH_BAR_ALIGN_WORD_MASK);

	if (unlikely(algin_offset >= ZXDH_BAR_MSG_ADDR_CHAN_INTERVAL)) {
		PMD_MSG_LOG(ERR, "algin_offset exceeds channel size!");
		return -1;
	}
	*(uint32_t *)(subchan_addr + algin_offset) = data;
	return 0;
}

static int zxdh_bar_chan_reg_read(uint64_t subchan_addr, uint32_t offset, uint32_t *pdata)
{
	uint32_t algin_offset = (offset & ZXDH_BAR_ALIGN_WORD_MASK);

	if (unlikely(algin_offset >= ZXDH_BAR_MSG_ADDR_CHAN_INTERVAL)) {
		PMD_MSG_LOG(ERR, "algin_offset exceeds channel size!");
		return -1;
	}
	*pdata = *(uint32_t *)(subchan_addr + algin_offset);
	return 0;
}

static uint16_t zxdh_bar_chan_msg_header_set(uint64_t subchan_addr,
						struct bar_msg_header *msg_header)
{
	uint32_t *data = (uint32_t *)msg_header;
	uint16_t idx;

	for (idx = 0; idx < (ZXDH_BAR_MSG_PLAYLOAD_OFFSET >> 2); idx++)
		zxdh_bar_chan_reg_write(subchan_addr, idx * 4, *(data + idx));

	return ZXDH_BAR_MSG_OK;
}

static uint16_t zxdh_bar_chan_msg_header_get(uint64_t subchan_addr,
		struct bar_msg_header *msg_header)
{
	uint32_t *data = (uint32_t *)msg_header;
	uint16_t idx;

	for (idx = 0; idx < (ZXDH_BAR_MSG_PLAYLOAD_OFFSET >> 2); idx++)
		zxdh_bar_chan_reg_read(subchan_addr, idx * 4, data + idx);

	return ZXDH_BAR_MSG_OK;
}

static uint16_t zxdh_bar_chan_msg_payload_set(uint64_t subchan_addr, uint8_t *msg, uint16_t len)
{
	uint32_t *data = (uint32_t *)msg;
	uint32_t count = (len >> 2);
	uint32_t ix;

	for (ix = 0; ix < count; ix++)
		zxdh_bar_chan_reg_write(subchan_addr, 4 * ix +
				ZXDH_BAR_MSG_PLAYLOAD_OFFSET, *(data + ix));

	uint32_t remain = (len & 0x3);

	if (remain) {
		uint32_t remain_data = 0;

		for (ix = 0; ix < remain; ix++)
			remain_data |= *((uint8_t *)(msg + len - remain + ix)) << (8 * ix);

		zxdh_bar_chan_reg_write(subchan_addr, 4 * count +
				ZXDH_BAR_MSG_PLAYLOAD_OFFSET, remain_data);
	}
	return ZXDH_BAR_MSG_OK;
}

static uint16_t zxdh_bar_chan_msg_payload_get(uint64_t subchan_addr, uint8_t *msg, uint16_t len)
{
	uint32_t *data = (uint32_t *)msg;
	uint32_t count = (len >> 2);
	uint32_t ix;

	for (ix = 0; ix < count; ix++)
		zxdh_bar_chan_reg_read(subchan_addr, 4 * ix +
			ZXDH_BAR_MSG_PLAYLOAD_OFFSET, (data + ix));

	uint32_t remain = (len & 0x3);

	if (remain) {
		uint32_t remain_data = 0;

		zxdh_bar_chan_reg_read(subchan_addr, 4 * count +
				ZXDH_BAR_MSG_PLAYLOAD_OFFSET, &remain_data);
		for (ix = 0; ix < remain; ix++)
			*((uint8_t *)(msg + (len - remain + ix))) = remain_data >> (8 * ix);
	}
	return ZXDH_BAR_MSG_OK;
}

static uint16_t zxdh_bar_chan_msg_valid_set(uint64_t subchan_addr, uint8_t valid_label)
{
	uint32_t data;

	zxdh_bar_chan_reg_read(subchan_addr, ZXDH_BAR_MSG_VALID_OFFSET, &data);
	data &= (~ZXDH_BAR_MSG_VALID_MASK);
	data |= (uint32_t)valid_label;
	zxdh_bar_chan_reg_write(subchan_addr, ZXDH_BAR_MSG_VALID_OFFSET, data);
	return ZXDH_BAR_MSG_OK;
}

static uint8_t temp_msg[ZXDH_BAR_MSG_ADDR_CHAN_INTERVAL];
static uint16_t zxdh_bar_chan_msg_send(uint64_t subchan_addr, void *payload_addr,
					uint16_t payload_len, struct bar_msg_header *msg_header)
{
	uint16_t ret = 0;
	ret = zxdh_bar_chan_msg_header_set(subchan_addr, msg_header);

	ret = zxdh_bar_chan_msg_header_get(subchan_addr,
				(struct bar_msg_header *)temp_msg);

	ret = zxdh_bar_chan_msg_payload_set(subchan_addr,
				(uint8_t *)(payload_addr), payload_len);

	ret = zxdh_bar_chan_msg_payload_get(subchan_addr,
				temp_msg, payload_len);

	ret = zxdh_bar_chan_msg_valid_set(subchan_addr, ZXDH_BAR_MSG_CHAN_USED);
	return ret;
}

static uint16_t zxdh_bar_msg_valid_stat_get(uint64_t subchan_addr)
{
	uint32_t data;

	zxdh_bar_chan_reg_read(subchan_addr, ZXDH_BAR_MSG_VALID_OFFSET, &data);
	if (ZXDH_BAR_MSG_CHAN_USABLE == (data & ZXDH_BAR_MSG_VALID_MASK))
		return ZXDH_BAR_MSG_CHAN_USABLE;

	return ZXDH_BAR_MSG_CHAN_USED;
}

static uint16_t zxdh_bar_chan_msg_poltag_set(uint64_t subchan_addr, uint8_t label)
{
	uint32_t data;

	zxdh_bar_chan_reg_read(subchan_addr, ZXDH_BAR_MSG_VALID_OFFSET, &data);
	data &= (~(uint32_t)ZXDH_BAR_MSG_POL_MASK);
	data |= ((uint32_t)label << ZXDH_BAR_MSG_POL_OFFSET);
	zxdh_bar_chan_reg_write(subchan_addr, ZXDH_BAR_MSG_VALID_OFFSET, data);
	return ZXDH_BAR_MSG_OK;
}

static uint16_t zxdh_bar_chan_sync_msg_reps_get(uint64_t subchan_addr,
					uint64_t recv_buffer, uint16_t buffer_len)
{
	struct bar_msg_header msg_header = {0};
	uint16_t msg_id = 0;
	uint16_t msg_len = 0;

	zxdh_bar_chan_msg_header_get(subchan_addr, &msg_header);
	msg_id = msg_header.msg_id;
	struct seqid_item *reps_info = &g_seqid_ring.reps_info_tbl[msg_id];

	if (reps_info->flag != ZXDH_REPS_INFO_FLAG_USED) {
		PMD_MSG_LOG(ERR, "msg_id %u unused", msg_id);
		return ZXDH_BAR_MSG_ERR_REPLY;
	}
	msg_len = msg_header.len;

	if (msg_len > buffer_len - 4) {
		PMD_MSG_LOG(ERR, "recv buffer len is: %u, but reply msg len is: %u",
				buffer_len, msg_len + 4);
		return ZXDH_BAR_MSG_ERR_REPSBUFF_LEN;
	}
	uint8_t *recv_msg = (uint8_t *)recv_buffer;

	zxdh_bar_chan_msg_payload_get(subchan_addr,
			recv_msg + ZXDH_REPS_HEADER_PAYLOAD_OFFSET, msg_len);
	*(uint16_t *)(recv_msg + ZXDH_REPS_HEADER_LEN_OFFSET) = msg_len;
	*recv_msg = ZXDH_REPS_HEADER_REPLYED; /* set reps's valid */
	return ZXDH_BAR_MSG_OK;
}

int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in, struct zxdh_msg_recviver_mem *result)
{
	struct bar_msg_header msg_header = {0};
	uint16_t seq_id = 0;
	uint64_t subchan_addr = 0;
	uint32_t time_out_cnt = 0;
	uint16_t valid = 0;
	int ret = 0;

	ret = zxdh_bar_chan_send_para_check(in, result);
	if (ret != ZXDH_BAR_MSG_OK)
		goto exit;

	ret = zxdh_bar_chan_save_recv_info(result, &seq_id);
	if (ret != ZXDH_BAR_MSG_OK)
		goto exit;

	zxdh_bar_chan_subchan_addr_get(in, &subchan_addr);

	msg_header.sync = ZXDH_BAR_CHAN_MSG_SYNC;
	msg_header.emec = in->emec;
	msg_header.usr  = 0;
	msg_header.rsv  = 0;
	msg_header.module_id  = in->module_id;
	msg_header.len        = in->payload_len;
	msg_header.msg_id     = seq_id;
	msg_header.src_pcieid = in->src_pcieid;
	msg_header.dst_pcieid = in->dst_pcieid;

	ret = zxdh_bar_chan_lock(in->src, in->dst, in->src_pcieid, in->virt_addr);
	if (ret != ZXDH_BAR_MSG_OK) {
		zxdh_bar_chan_msgid_free(seq_id);
		goto exit;
	}
	zxdh_bar_chan_msg_send(subchan_addr, in->payload_addr, in->payload_len, &msg_header);

	do {
		rte_delay_us_block(ZXDH_BAR_MSG_POLLING_SPAN);
		valid = zxdh_bar_msg_valid_stat_get(subchan_addr);
		++time_out_cnt;
	} while ((time_out_cnt < ZXDH_BAR_MSG_TIMEOUT_TH) && (valid == ZXDH_BAR_MSG_CHAN_USED));

	if (time_out_cnt == ZXDH_BAR_MSG_TIMEOUT_TH && valid != ZXDH_BAR_MSG_CHAN_USABLE) {
		zxdh_bar_chan_msg_valid_set(subchan_addr, ZXDH_BAR_MSG_CHAN_USABLE);
		zxdh_bar_chan_msg_poltag_set(subchan_addr, 0);
		PMD_MSG_LOG(ERR, "BAR MSG ERR: chan type time out.");
		ret = ZXDH_BAR_MSG_ERR_TIME_OUT;
	} else {
		ret = zxdh_bar_chan_sync_msg_reps_get(subchan_addr,
					(uint64_t)result->recv_buffer, result->buffer_len);
	}
	zxdh_bar_chan_msgid_free(seq_id);
	zxdh_bar_chan_unlock(in->src, in->dst, in->src_pcieid, in->virt_addr);

exit:
	return ret;
}

static int bar_get_sum(uint8_t *ptr, uint8_t len)
{
	uint64_t sum = 0;
	int idx;

	for (idx = 0; idx < len; idx++)
		sum += *(ptr + idx);

	return (uint16_t)sum;
}

static int zxdh_bar_chan_enable(struct msix_para *para, uint16_t *vport)
{
	struct bar_recv_msg recv_msg = {0};
	int ret = 0;
	int check_token = 0;
	int sum_res = 0;

	if (!para)
		return ZXDH_BAR_MSG_ERR_NULL;

	struct msix_msg msix_msg = {
		.pcie_id = para->pcie_id,
		.vector_risc = para->vector_risc,
		.vector_pfvf = para->vector_pfvf,
		.vector_mpf = para->vector_mpf,
	};
	struct zxdh_pci_bar_msg in = {
		.virt_addr = para->virt_addr,
		.payload_addr = &msix_msg,
		.payload_len = sizeof(msix_msg),
		.emec = 0,
		.src = para->driver_type,
		.dst = ZXDH_MSG_CHAN_END_RISC,
		.module_id = ZXDH_BAR_MODULE_MISX,
		.src_pcieid = para->pcie_id,
		.dst_pcieid = 0,
		.usr = 0,
	};

	struct zxdh_msg_recviver_mem result = {
		.recv_buffer = &recv_msg,
		.buffer_len = sizeof(recv_msg),
	};

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret != ZXDH_BAR_MSG_OK)
		return -ret;

	check_token = recv_msg.msix_reps.check;
	sum_res = bar_get_sum((uint8_t *)&msix_msg, sizeof(msix_msg));

	if (check_token != sum_res) {
		PMD_MSG_LOG(ERR, "expect token: 0x%x, get token: 0x%x.", sum_res, check_token);
		return ZXDH_BAR_MSG_ERR_REPLY;
	}
	*vport = recv_msg.msix_reps.vport;
	PMD_MSG_LOG(DEBUG, "vport of pcieid: 0x%x get success.", para->pcie_id);
	return ZXDH_BAR_MSG_OK;
}

int zxdh_msg_chan_enable(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	struct msix_para misx_info = {
		.vector_risc = ZXDH_MSIX_FROM_RISCV,
		.vector_pfvf = ZXDH_MSIX_FROM_PFVF,
		.vector_mpf  = ZXDH_MSIX_FROM_MPF,
		.pcie_id     = hw->pcie_id,
		.driver_type = hw->is_pf ? ZXDH_MSG_CHAN_END_PF : ZXDH_MSG_CHAN_END_VF,
		.virt_addr   = (uint64_t)(hw->bar_addr[ZXDH_BAR0_INDEX] + ZXDH_CTRLCH_OFFSET),
	};

	return zxdh_bar_chan_enable(&misx_info, &hw->vport.vport);
}

int zxdh_msg_chan_hwlock_init(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	if (!hw->is_pf)
		return 0;
	return bar_chan_pf_init_spinlock(hw->pcie_id, (uint64_t)(hw->bar_addr[ZXDH_BAR0_INDEX]));
}
