/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#include <stdbool.h>

#include <rte_common.h>
#include <rte_memcpy.h>
#include <pthread.h>
#include <rte_cycles.h>
#include <inttypes.h>
#include <rte_malloc.h>

#include "zxdh_logs.h"
#include "zxdh_msg.h"

#define REPS_INFO_FLAG_USABLE  0x00
#define REPS_INFO_FLAG_USED    0xa0

#define BDF_ECAM(bus, devid, func)   (((bus & 0xff) << 8) | (func & 0x07) | ((devid & 0x1f) << 3))

/**
 * common.ko will work in 5 scenarios
 * 1: SCENE_HOST_IN_DPU  : host in DPU card
 * 2: SCENE_ZF_IN_DPU    : zf   in DPU card
 * 3: SCENE_NIC_WITH_DDR : inic with DDR
 * 4: SCENE_NIC_NO_DDR   : inic without DDR
 * 5: SCENE_STD_NIC      : std card
 */
#ifdef SCENE_HOST_IN_DPU
#define BAR_PF_NUM             31
#define BAR_VF_NUM             1024
#define BAR_INDEX_PF_TO_VF     1
#define BAR_INDEX_MPF_TO_MPF   1
#define BAR_INDEX_MPF_TO_PFVF  0xff
#define BAR_INDEX_PFVF_TO_MPF  0xff
#endif

#ifdef SCENE_ZF_IN_DPU
#define BAR_PF_NUM             7
#define BAR_VF_NUM             128
#define BAR_INDEX_PF_TO_VF     0xff
#define BAR_INDEX_MPF_TO_MPF   1
#define BAR_INDEX_MPF_TO_PFVF  0xff
#define BAR_INDEX_PFVF_TO_MPF  0xff
#endif

#ifdef SCENE_NIC_WITH_DDR
#define BAR_PF_NUM             31
#define BAR_VF_NUM             1024
#define BAR_INDEX_PF_TO_VF     1
#define BAR_INDEX_MPF_TO_MPF   0xff
#define BAR_INDEX_MPF_TO_PFVF  0xff
#define BAR_INDEX_PFVF_TO_MPF  0xff
#endif

#ifdef SCENE_NIC_NO_DDR
#define BAR_PF_NUM             31
#define BAR_VF_NUM             1024
#define BAR_INDEX_PF_TO_VF     1
#define BAR_INDEX_MPF_TO_MPF   0xff
#define BAR_INDEX_MPF_TO_PFVF  1
#define BAR_INDEX_PFVF_TO_MPF  2
#endif

#ifdef SCENE_STD_NIC
#define BAR_PF_NUM             7
#define BAR_VF_NUM             256
#define BAR_INDEX_PF_TO_VF     1
#define BAR_INDEX_MPF_TO_MPF   0xff
#define BAR_INDEX_MPF_TO_PFVF  1
#define BAR_INDEX_PFVF_TO_MPF  2
#endif

#define SCENE_TEST
#ifdef SCENE_TEST
#define BAR_PF_NUM             7
#define BAR_VF_NUM             256
#define BAR_INDEX_PF_TO_VF     0
#define BAR_INDEX_MPF_TO_MPF   0xff
#define BAR_INDEX_MPF_TO_PFVF  0
#define BAR_INDEX_PFVF_TO_MPF  0
#endif

/**
 * 0: left 2K,    1: right 2K
 * src/dst: TO_RISC, TO_PFVF, TO_MPF
 * MPF:       0         0       0
 * PF:        0         0       1
 * VF:        0         1       1
 **/
#define BAR_MSG_SRC_NUM   3
#define BAR_MSG_SRC_MPF   0
#define BAR_MSG_SRC_PF    1
#define BAR_MSG_SRC_VF    2
#define BAR_MSG_SRC_ERR   0xff

#define BAR_MSG_DST_NUM   3
#define BAR_MSG_DST_RISC  0
#define BAR_MSG_DST_MPF   2
#define BAR_MSG_DST_PFVF  1
#define BAR_MSG_DST_ERR   0xff

#define BAR_SUBCHAN_INDEX_SEND  0
#define BAR_SUBCHAN_INDEX_RECV  1
#define BAR_SEQID_NUM_MAX  256

#define BAR_ALIGN_WORD_MASK  0xfffffffc
#define BAR_MSG_VALID_MASK    1
#define BAR_MSG_VALID_OFFSET  0

#define BAR_MSG_CHAN_USABLE  0
#define BAR_MSG_CHAN_USED    1

#define LOCK_TYPE_HARD  (1)
#define LOCK_TYPE_SOFT  (0)
#define BAR_INDEX_TO_RISC  0

#define BAR_MSG_POL_MASK    (0x10)
#define BAR_MSG_POL_OFFSET  (4)

#define REPS_HEADER_LEN_OFFSET      1
#define REPS_HEADER_PAYLOAD_OFFSET  4
#define REPS_HEADER_REPLYED         0xff

#define READ_CHECK  1

uint8_t subchan_id_tbl[BAR_MSG_SRC_NUM][BAR_MSG_DST_NUM] = {
	{BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_SEND},
	{BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_RECV},
	{BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_RECV, BAR_SUBCHAN_INDEX_RECV}
};

uint8_t chan_id_tbl[BAR_MSG_SRC_NUM][BAR_MSG_DST_NUM] = {
	{BAR_INDEX_TO_RISC, BAR_INDEX_MPF_TO_PFVF, BAR_INDEX_MPF_TO_MPF},
	{BAR_INDEX_TO_RISC, BAR_INDEX_PF_TO_VF,    BAR_INDEX_PFVF_TO_MPF},
	{BAR_INDEX_TO_RISC, BAR_INDEX_PF_TO_VF,    BAR_INDEX_PFVF_TO_MPF}
};

uint8_t lock_type_tbl[BAR_MSG_SRC_NUM][BAR_MSG_DST_NUM] = {
	{LOCK_TYPE_HARD, LOCK_TYPE_HARD, LOCK_TYPE_HARD},
	{LOCK_TYPE_SOFT, LOCK_TYPE_SOFT, LOCK_TYPE_HARD},
	{LOCK_TYPE_HARD, LOCK_TYPE_HARD, LOCK_TYPE_HARD}
};

#define PCIEID_IS_PF_MASK   (0x0800)
#define PCIEID_PF_IDX_MASK  (0x0700)
#define PCIEID_VF_IDX_MASK  (0x00ff)
#define PCIEID_EP_IDX_MASK  (0x7000)
/* PCIEID bit field offset */
#define PCIEID_PF_IDX_OFFSET  (8)
#define PCIEID_EP_IDX_OFFSET  (12)

#define MAX_EP_NUM     (4)
#define PF_NUM_PER_EP  (8)
#define VF_NUM_PER_PF  (32)

#define MULTIPLY_BY_8(x)    ((x) << 3)
#define MULTIPLY_BY_32(x)   ((x) << 5)
#define MULTIPLY_BY_256(x)  ((x) << 8)

#define MAX_HARD_SPINLOCK_NUM        (511)
#define MAX_HARD_SPINLOCK_ASK_TIMES  (1000)
#define SPINLOCK_POLLING_SPAN_US     (100)

#define LOCK_MASTER_ID_MASK                (0x8000)
/* bar offset */
#define BAR0_CHAN_RISC_OFFSET              (0x2000)
#define BAR0_CHAN_PFVF_OFFSET              (0x3000)
#define BAR0_SPINLOCK_OFFSET               (0x4000)
#define FW_SHRD_OFFSET                     (0x5000)
#define FW_SHRD_INNER_HW_LABEL_PAT         (0x800)
#define HW_LABEL_OFFSET                    (FW_SHRD_OFFSET + FW_SHRD_INNER_HW_LABEL_PAT)

#define CHAN_RISC_SPINLOCK_OFFSET          (BAR0_SPINLOCK_OFFSET - BAR0_CHAN_RISC_OFFSET)
#define CHAN_PFVF_SPINLOCK_OFFSET          (BAR0_SPINLOCK_OFFSET - BAR0_CHAN_PFVF_OFFSET)
#define CHAN_RISC_LABEL_OFFSET             (HW_LABEL_OFFSET - BAR0_CHAN_RISC_OFFSET)
#define CHAN_PFVF_LABEL_OFFSET             (HW_LABEL_OFFSET - BAR0_CHAN_PFVF_OFFSET)

#define RSC_TBL_CONTENT_LEN_MAX  (257 * 2)
#define TBL_MSG_PRO_SUCCESS  0xaa

zxdh_bar_chan_msg_recv_callback msg_recv_func_tbl[BAR_MSG_MODULE_NUM];

struct dev_stat {
	bool is_mpf_scanned;
	bool is_res_init;
	int16_t dev_cnt; /* probe cnt */
};
struct dev_stat g_dev_stat = {0};

static uint8_t __bar_msg_src_index_trans(uint8_t src)
{
	uint8_t src_index = 0;

	switch (src) {
	case MSG_CHAN_END_MPF:
		src_index = BAR_MSG_SRC_MPF;
		break;
	case MSG_CHAN_END_PF:
		src_index = BAR_MSG_SRC_PF;
		break;
	case MSG_CHAN_END_VF:
		src_index = BAR_MSG_SRC_VF;
		break;
	default:
		src_index = BAR_MSG_SRC_ERR;
		break;
	}
	return src_index;
}

static uint8_t __bar_msg_dst_index_trans(uint8_t dst)
{
	uint8_t dst_index = 0;

	switch (dst) {
	case MSG_CHAN_END_MPF:
		dst_index = BAR_MSG_DST_MPF;
		break;
	case MSG_CHAN_END_PF:
		dst_index = BAR_MSG_DST_PFVF;
		break;
	case MSG_CHAN_END_VF:
		dst_index = BAR_MSG_DST_PFVF;
		break;
	case MSG_CHAN_END_RISC:
		dst_index = BAR_MSG_DST_RISC;
		break;
	default:
		dst_index = BAR_MSG_SRC_ERR;
		break;
	}
	return dst_index;
}

struct seqid_item {
	void *reps_addr;
	uint16_t id;
	uint16_t buffer_len;
	uint16_t flag;
};

struct seqid_ring {
	uint16_t cur_id;
	pthread_spinlock_t lock;
	struct seqid_item reps_info_tbl[BAR_SEQID_NUM_MAX];
};
struct seqid_ring g_seqid_ring = {0};

static int __bar_chan_msgid_allocate(uint16_t *msgid)
{
	struct seqid_item *seqid_reps_info = NULL;

	pthread_spin_lock(&g_seqid_ring.lock);
	uint16_t g_id = g_seqid_ring.cur_id;
	uint16_t count = 0;

	do {
		count++;
		++g_id;
		g_id %= BAR_SEQID_NUM_MAX;
		seqid_reps_info = &g_seqid_ring.reps_info_tbl[g_id];
	} while ((seqid_reps_info->flag != REPS_INFO_FLAG_USABLE) && (count < BAR_SEQID_NUM_MAX));
	int rc;

	if (count >= BAR_SEQID_NUM_MAX) {
		rc = -1;
		goto out;
	}
	seqid_reps_info->flag = REPS_INFO_FLAG_USED;
	g_seqid_ring.cur_id = g_id;
	*msgid = g_id;
	rc = BAR_MSG_OK;

out:
	pthread_spin_unlock(&g_seqid_ring.lock);
	return rc;
}

static uint16_t __bar_chan_save_recv_info(struct zxdh_msg_recviver_mem *result, uint16_t *msg_id)
{
	int ret = __bar_chan_msgid_allocate(msg_id);

	if (ret != BAR_MSG_OK)
		return BAR_MSG_ERR_MSGID;

	PMD_MSG_LOG(DEBUG, "allocate msg_id: %u", *msg_id);
	struct seqid_item *reps_info = &g_seqid_ring.reps_info_tbl[*msg_id];

	reps_info->reps_addr = result->recv_buffer;
	reps_info->buffer_len = result->buffer_len;
	return BAR_MSG_OK;
}

static void __bar_chan_msgid_free(uint16_t msg_id)
{
	struct seqid_item *seqid_reps_info = &g_seqid_ring.reps_info_tbl[msg_id];

	pthread_spin_lock(&g_seqid_ring.lock);
	seqid_reps_info->flag = REPS_INFO_FLAG_USABLE;
	PMD_MSG_LOG(DEBUG, "free msg_id: %u", msg_id);
	pthread_spin_unlock(&g_seqid_ring.lock);
}

static uint64_t subchan_addr_cal(uint64_t virt_addr, uint8_t chan_id, uint8_t subchan_id)
{
	return virt_addr + (2 * chan_id + subchan_id) * BAR_MSG_ADDR_CHAN_INTERVAL;
}

static uint16_t __bar_chan_subchan_addr_get(struct zxdh_pci_bar_msg *in, uint64_t *subchan_addr)
{
	uint8_t src_index = __bar_msg_src_index_trans(in->src);
	uint8_t dst_index = __bar_msg_dst_index_trans(in->dst);
	uint16_t chan_id = chan_id_tbl[src_index][dst_index];
	uint16_t subchan_id = subchan_id_tbl[src_index][dst_index];

	*subchan_addr = subchan_addr_cal(in->virt_addr, chan_id, subchan_id);
	return BAR_MSG_OK;
}

static int __bar_chan_reg_write(uint64_t subchan_addr, uint32_t offset, uint32_t data)
{
	uint32_t algin_offset = (offset & BAR_ALIGN_WORD_MASK);

	if (unlikely(algin_offset >= BAR_MSG_ADDR_CHAN_INTERVAL)) {
		PMD_MSG_LOG(ERR, "subchan addr: %" PRIu64 "offset: %" PRIu32,
			subchan_addr, algin_offset);
		return -1;
	}
	*(uint32_t *)(subchan_addr + algin_offset) = data;
	return 0;
}

static int __bar_chan_reg_read(uint64_t subchan_addr, uint32_t offset, uint32_t *pdata)
{
	uint32_t algin_offset = (offset & BAR_ALIGN_WORD_MASK);

	if (unlikely(algin_offset >= BAR_MSG_ADDR_CHAN_INTERVAL)) {
		PMD_MSG_LOG(ERR, "subchan addr: %" PRIu64 "offset: %" PRIu32,
			subchan_addr, algin_offset);
		return -1;
	}
	*pdata = *(uint32_t *)(subchan_addr + algin_offset);
	return 0;
}

static uint16_t __bar_chan_msg_header_set(uint64_t subchan_addr, struct bar_msg_header *msg_header)
{
	uint32_t *data = (uint32_t *)msg_header;
	uint16_t idx;

	for (idx = 0; idx < (BAR_MSG_PLAYLOAD_OFFSET >> 2); idx++)
		__bar_chan_reg_write(subchan_addr, idx * 4, *(data + idx));

	return BAR_MSG_OK;
}

static uint16_t __bar_chan_msg_header_get(uint64_t subchan_addr, struct bar_msg_header *msg_header)
{
	uint32_t *data = (uint32_t *)msg_header;
	uint16_t idx;

	for (idx = 0; idx < (BAR_MSG_PLAYLOAD_OFFSET >> 2); idx++)
		__bar_chan_reg_read(subchan_addr, idx * 4, data + idx);

	return BAR_MSG_OK;
}

static uint16_t __bar_chan_msg_payload_set(uint64_t subchan_addr, uint8_t *msg, uint16_t len)
{
	uint32_t *data = (uint32_t *)msg;
	uint32_t count = (len >> 2); /* 4B unit */
	uint32_t ix;

	for (ix = 0; ix < count; ix++)
		__bar_chan_reg_write(subchan_addr, 4 * ix + BAR_MSG_PLAYLOAD_OFFSET, *(data + ix));

	/* not 4B align part */
	uint32_t remain = (len & 0x3);

	if (remain) {
		uint32_t remain_data = 0;

		for (ix = 0; ix < remain; ix++)
			remain_data |= *((uint8_t *)(msg + len - remain + ix)) << (8 * ix);

		__bar_chan_reg_write(subchan_addr, 4 * count +
				BAR_MSG_PLAYLOAD_OFFSET, remain_data);
	}
	return BAR_MSG_OK;
}

static uint16_t __bar_chan_msg_payload_get(uint64_t subchan_addr, uint8_t *msg, uint16_t len)
{
	uint32_t *data = (uint32_t *)msg;
	uint32_t count = (len >> 2);
	uint32_t ix;

	for (ix = 0; ix < count; ix++)
		__bar_chan_reg_read(subchan_addr, 4 * ix + BAR_MSG_PLAYLOAD_OFFSET, (data + ix));

	uint32_t remain = (len & 0x3);

	if (remain) {
		uint32_t remain_data = 0;

		__bar_chan_reg_read(subchan_addr, 4 * count +
				BAR_MSG_PLAYLOAD_OFFSET, &remain_data);
		for (ix = 0; ix < remain; ix++)
			*((uint8_t *)(msg + (len - remain + ix))) = remain_data >> (8 * ix);
	}
	return BAR_MSG_OK;
}

static uint16_t __bar_chan_msg_valid_set(uint64_t subchan_addr, uint8_t valid_label)
{
	uint32_t data;

	__bar_chan_reg_read(subchan_addr, BAR_MSG_VALID_OFFSET, &data);
	data &= (~BAR_MSG_VALID_MASK);
	data |= (uint32_t)valid_label;
	__bar_chan_reg_write(subchan_addr, BAR_MSG_VALID_OFFSET, data);
	return BAR_MSG_OK;
}

static uint16_t __bar_msg_valid_stat_get(uint64_t subchan_addr)
{
	uint32_t data;

	__bar_chan_reg_read(subchan_addr, BAR_MSG_VALID_OFFSET, &data);
	if (BAR_MSG_CHAN_USABLE == (data & BAR_MSG_VALID_MASK))
		return BAR_MSG_CHAN_USABLE;

	return BAR_MSG_CHAN_USED;
}

#if READ_CHECK
static uint8_t temp_msg[BAR_MSG_ADDR_CHAN_INTERVAL];
#endif
static uint16_t __bar_chan_msg_send(uint64_t subchan_addr, void *payload_addr,
					uint16_t payload_len, struct bar_msg_header *msg_header)
{
	__bar_chan_msg_header_set(subchan_addr, msg_header);
#if READ_CHECK
	__bar_chan_msg_header_get(subchan_addr, (struct bar_msg_header *)temp_msg);
#endif
	__bar_chan_msg_payload_set(subchan_addr, (uint8_t *)(payload_addr), payload_len);
#if READ_CHECK
	__bar_chan_msg_payload_get(subchan_addr, temp_msg, payload_len);
#endif
	__bar_chan_msg_valid_set(subchan_addr, BAR_MSG_CHAN_USED);
	return BAR_MSG_OK;
}

static uint16_t __bar_chan_msg_poltag_set(uint64_t subchan_addr, uint8_t label)
{
	uint32_t data;

	__bar_chan_reg_read(subchan_addr, BAR_MSG_VALID_OFFSET, &data);
	data &= (~(uint32_t)BAR_MSG_POL_MASK);
	data |= ((uint32_t)label << BAR_MSG_POL_OFFSET);
	__bar_chan_reg_write(subchan_addr, BAR_MSG_VALID_OFFSET, data);
	return BAR_MSG_OK;
}

static uint16_t __bar_chan_sync_msg_reps_get(uint64_t subchan_addr,
					uint64_t recv_buffer, uint16_t buffer_len)
{
	struct bar_msg_header msg_header = {0};
	uint16_t msg_id = 0;
	uint16_t msg_len = 0;

	__bar_chan_msg_header_get(subchan_addr, &msg_header);
	msg_id = msg_header.msg_id;
	struct seqid_item *reps_info = &g_seqid_ring.reps_info_tbl[msg_id];

	if (reps_info->flag != REPS_INFO_FLAG_USED) {
		PMD_MSG_LOG(ERR, "msg_id %u unused", msg_id);
		return BAR_MSG_ERR_REPLY;
	}
	msg_len = msg_header.len;

	if (msg_len > buffer_len - 4) {
		PMD_MSG_LOG(ERR, "recv buffer len is: %u, but reply msg len is: %u",
				buffer_len, msg_len + 4);
		return BAR_MSG_ERR_REPSBUFF_LEN;
	}
	uint8_t *recv_msg = (uint8_t *)recv_buffer;

	__bar_chan_msg_payload_get(subchan_addr, recv_msg + REPS_HEADER_PAYLOAD_OFFSET, msg_len);
	*(uint16_t *)(recv_msg + REPS_HEADER_LEN_OFFSET) = msg_len;
	*recv_msg = REPS_HEADER_REPLYED; /* set reps's valid */
	return BAR_MSG_OK;
}

static int __bar_chan_send_para_check(struct zxdh_pci_bar_msg *in,
					struct zxdh_msg_recviver_mem *result)
{
	if (in == NULL || result == NULL) {
		PMD_MSG_LOG(ERR, "send para ERR: null para.");
		return BAR_MSG_ERR_NULL_PARA;
	}
	uint8_t src_index = __bar_msg_src_index_trans(in->src);
	uint8_t dst_index = __bar_msg_dst_index_trans(in->dst);

	if (src_index == BAR_MSG_SRC_ERR || dst_index == BAR_MSG_DST_ERR) {
		PMD_MSG_LOG(ERR, "send para ERR: chan doesn't exist.");
		return BAR_MSG_ERR_TYPE;
	}
	if (in->module_id >= BAR_MSG_MODULE_NUM) {
		PMD_MSG_LOG(ERR, "send para ERR: invalid module_id: %d.", in->module_id);
		return BAR_MSG_ERR_MODULE;
	}
	if (in->payload_addr == NULL) {
		PMD_MSG_LOG(ERR, "send para ERR: null message.");
		return BAR_MSG_ERR_BODY_NULL;
	}
	if (in->payload_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		PMD_MSG_LOG(ERR, "send para ERR: len %d is too long.", in->payload_len);
		return BAR_MSG_ERR_LEN;
	}
	if (in->virt_addr == 0 || result->recv_buffer == NULL) {
		PMD_MSG_LOG(ERR, "send para ERR: virt_addr or recv_buffer is NULL.");
		return BAR_MSG_ERR_VIRTADDR_NULL;
	}
	if (result->buffer_len < REPS_HEADER_PAYLOAD_OFFSET)
		PMD_MSG_LOG(ERR,
			"recv buffer len: %" PRIu64 " is short than mininal 4 bytes\n",
			result->buffer_len);

	return BAR_MSG_OK;
}

static uint16_t pcie_id_to_hard_lock(uint16_t src_pcieid, uint8_t dst)
{
	uint16_t lock_id = 0;
	uint16_t pf_idx = (src_pcieid & PCIEID_PF_IDX_MASK) >> PCIEID_PF_IDX_OFFSET;
	uint16_t ep_idx = (src_pcieid & PCIEID_EP_IDX_MASK) >> PCIEID_EP_IDX_OFFSET;

	switch (dst) {
	/* msg to risc */
	case MSG_CHAN_END_RISC:
		lock_id = MULTIPLY_BY_8(ep_idx) + pf_idx;
		break;
	/* msg to pf/vf */
	case MSG_CHAN_END_VF:
	case MSG_CHAN_END_PF:
		lock_id = MULTIPLY_BY_8(ep_idx) + pf_idx + MULTIPLY_BY_8(1 + MAX_EP_NUM);
		break;
	default:
		lock_id = 0;
		break;
	}
	if (lock_id >= MAX_HARD_SPINLOCK_NUM)
		lock_id = 0;

	return lock_id;
}

static uint8_t spinklock_read(uint64_t virt_lock_addr, uint32_t lock_id)
{
	return *(volatile uint8_t *)((uint64_t)virt_lock_addr + (uint64_t)lock_id);
}

static void spinlock_write(uint64_t virt_lock_addr, uint32_t lock_id, uint8_t data)
{
	*(volatile uint8_t *)((uint64_t)virt_lock_addr + (uint64_t)lock_id) = data;
}

static void label_write(uint64_t label_lock_addr, uint32_t lock_id, uint16_t value)
{
	*(volatile uint16_t *)(label_lock_addr + lock_id * 2) = value;
}

static int32_t zxdh_spinlock_lock(uint32_t virt_lock_id, uint64_t virt_addr,
					uint64_t label_addr, uint16_t master_id)
{
	uint32_t lock_rd_cnt = 0;

	do {
		/* read to lock */
		uint8_t spl_val = spinklock_read(virt_addr, virt_lock_id);

		if (spl_val == 0) {
			label_write((uint64_t)label_addr, virt_lock_id, master_id);
			break;
		}
		rte_delay_us_block(SPINLOCK_POLLING_SPAN_US);
		lock_rd_cnt++;
	} while (lock_rd_cnt < MAX_HARD_SPINLOCK_ASK_TIMES);
	if (lock_rd_cnt >= MAX_HARD_SPINLOCK_ASK_TIMES)
		return -1;

	return 0;
}

static int32_t zxdh_spinlock_unlock(uint32_t virt_lock_id, uint64_t virt_addr, uint64_t label_addr)
{
	label_write((uint64_t)label_addr, virt_lock_id, 0);
	spinlock_write(virt_addr, virt_lock_id, 0);
	return 0;
}

int pf_recv_bar_msg(void *pay_load __rte_unused,
					uint16_t len __rte_unused,
					void *reps_buffer __rte_unused,
					uint16_t *reps_len __rte_unused,
					void *eth_dev __rte_unused)
{
	/* todo later provided*/
	return 0;
}

int vf_recv_bar_msg(void *pay_load __rte_unused,
					uint16_t len __rte_unused,
					void *reps_buffer __rte_unused,
					uint16_t *reps_len __rte_unused,
					void *eth_dev __rte_unused)
{
	/* todo later provided*/
	return 0;
}

static int bar_hard_lock(uint16_t src_pcieid, uint8_t dst, uint64_t virt_addr)
{
	int ret = 0;
	uint16_t lockid = pcie_id_to_hard_lock(src_pcieid, dst);

	PMD_MSG_LOG(DEBUG, "dev pcieid: 0x%x lock, get hardlockid: %u\n", src_pcieid, lockid);
	if (dst == MSG_CHAN_END_RISC)
		ret = zxdh_spinlock_lock(lockid, virt_addr + CHAN_RISC_SPINLOCK_OFFSET,
					virt_addr + CHAN_RISC_LABEL_OFFSET,
					src_pcieid | LOCK_MASTER_ID_MASK);
	else
		ret = zxdh_spinlock_lock(lockid, virt_addr + CHAN_PFVF_SPINLOCK_OFFSET,
					virt_addr + CHAN_PFVF_LABEL_OFFSET,
					src_pcieid | LOCK_MASTER_ID_MASK);

	return ret;
}

static void bar_hard_unlock(uint16_t src_pcieid, uint8_t dst, uint64_t virt_addr)
{
	uint16_t lockid = pcie_id_to_hard_lock(src_pcieid, dst);

	PMD_MSG_LOG(DEBUG, "dev pcieid: 0x%x unlock, get hardlockid: %u\n", src_pcieid, lockid);
	if (dst == MSG_CHAN_END_RISC)
		zxdh_spinlock_unlock(lockid, virt_addr + CHAN_RISC_SPINLOCK_OFFSET,
				virt_addr + CHAN_RISC_LABEL_OFFSET);
	else
		zxdh_spinlock_unlock(lockid, virt_addr + CHAN_PFVF_SPINLOCK_OFFSET,
				virt_addr + CHAN_PFVF_LABEL_OFFSET);
}
/**
 * Fun: PF init hard_spinlock addr
 * @pcie_id: pf's pcie_id
 * @bar_base_addr:
 */
int bar_chan_pf_init_spinlock(uint16_t pcie_id, uint64_t bar_base_addr)
{
	int lock_id = pcie_id_to_hard_lock(pcie_id, MSG_CHAN_END_RISC);

	zxdh_spinlock_unlock(lock_id, bar_base_addr + BAR0_SPINLOCK_OFFSET,
			bar_base_addr + HW_LABEL_OFFSET);
	lock_id = pcie_id_to_hard_lock(pcie_id, MSG_CHAN_END_VF);
	zxdh_spinlock_unlock(lock_id, bar_base_addr + BAR0_SPINLOCK_OFFSET,
			bar_base_addr + HW_LABEL_OFFSET);
	return 0;
}

/**
 * Fun: lock the channel
 */
pthread_spinlock_t chan_lock;
static int bar_chan_lock(uint8_t src, uint8_t dst, uint16_t src_pcieid, uint64_t virt_addr)
{
	int ret = 0;
	uint8_t src_index = __bar_msg_src_index_trans(src);
	uint8_t dst_index = __bar_msg_dst_index_trans(dst);

	if (src_index == BAR_MSG_SRC_ERR || dst_index == BAR_MSG_DST_ERR) {
		PMD_MSG_LOG(ERR, "lock ERR: chan doesn't exist.\n");
		return BAR_MSG_ERR_TYPE;
	}
	uint16_t idx = lock_type_tbl[src_index][dst_index];

	if (idx == LOCK_TYPE_SOFT)
		pthread_spin_lock(&chan_lock);
	else
		ret = bar_hard_lock(src_pcieid, dst, virt_addr);

	if (ret != 0)
		PMD_MSG_LOG(ERR, "dev: 0x%x failed to lock.\n", src_pcieid);

	return ret;
}
/**
 * Fun: unlock the channel
 */
static int bar_chan_unlock(uint8_t src, uint8_t dst, uint16_t src_pcieid, uint64_t virt_addr)
{
	uint8_t src_index = __bar_msg_src_index_trans(src);
	uint8_t dst_index = __bar_msg_dst_index_trans(dst);

	if (src_index == BAR_MSG_SRC_ERR || dst_index == BAR_MSG_DST_ERR) {
		PMD_MSG_LOG(ERR, "unlock ERR: chan doesn't exist.\n");
		return BAR_MSG_ERR_TYPE;
	}
	uint16_t idx = lock_type_tbl[src_index][dst_index];

	if (idx == LOCK_TYPE_SOFT)
		pthread_spin_unlock(&chan_lock);
	else
		bar_hard_unlock(src_pcieid, dst, virt_addr);

	return BAR_MSG_OK;
}

int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in, struct zxdh_msg_recviver_mem *result)
{
	uint16_t ret = __bar_chan_send_para_check(in, result);

	if (ret != BAR_MSG_OK)
		goto exit;

	uint16_t seq_id;

	ret = __bar_chan_save_recv_info(result, &seq_id);
	if (ret != BAR_MSG_OK)
		goto exit;

	uint64_t subchan_addr;

	__bar_chan_subchan_addr_get(in, &subchan_addr);
	struct bar_msg_header msg_header = {0};

	msg_header.sync = BAR_CHAN_MSG_SYNC;
	msg_header.emec = in->emec;
	msg_header.usr  = 0;
	msg_header.rsv  = 0;
	msg_header.module_id  = in->module_id;
	msg_header.len        = in->payload_len;
	msg_header.msg_id     = seq_id;
	msg_header.src_pcieid = in->src_pcieid;
	msg_header.dst_pcieid = in->dst_pcieid;

	ret = bar_chan_lock(in->src, in->dst, in->src_pcieid, in->virt_addr);
	if (ret != BAR_MSG_OK) {
		__bar_chan_msgid_free(seq_id);
		goto exit;
	}
	__bar_chan_msg_send(subchan_addr, in->payload_addr, in->payload_len, &msg_header);
	/* wait unset valid */
	uint32_t time_out_cnt = 0;
	uint16_t valid;

	do {
		rte_delay_us_block(BAR_MSG_POLLING_SPAN);
		valid = __bar_msg_valid_stat_get(subchan_addr);
		++time_out_cnt;
	} while ((time_out_cnt < BAR_MSG_TIMEOUT_TH) && (valid == BAR_MSG_CHAN_USED));

	if ((time_out_cnt == BAR_MSG_TIMEOUT_TH) && (valid != BAR_MSG_CHAN_USABLE)) {
		__bar_chan_msg_valid_set(subchan_addr, BAR_MSG_CHAN_USABLE);
		__bar_chan_msg_poltag_set(subchan_addr, 0);
		PMD_MSG_LOG(ERR, "BAR MSG ERR: chan type time out.");
		ret = BAR_MSG_ERR_TIME_OUT;
	} else {
		ret = __bar_chan_sync_msg_reps_get(subchan_addr,
					(uint64_t)result->recv_buffer, result->buffer_len);
	}
	__bar_chan_msgid_free(seq_id);
	bar_chan_unlock(in->src, in->dst, in->src_pcieid, in->virt_addr);

exit:
	return ret;
}

static uint64_t recv_addr_get(uint8_t src_type, uint8_t dst_type, uint64_t virt_addr)
{
	uint8_t src = __bar_msg_dst_index_trans(src_type);
	uint8_t dst = __bar_msg_src_index_trans(dst_type);

	if (src == BAR_MSG_SRC_ERR || dst == BAR_MSG_DST_ERR)
		return 0;

	uint8_t chan_id = chan_id_tbl[dst][src];
	uint8_t subchan_id = 1 - subchan_id_tbl[dst][src];

	return subchan_addr_cal(virt_addr, chan_id, subchan_id);
}

static uint64_t reply_addr_get(uint8_t sync, uint8_t src_type, uint8_t dst_type, uint64_t virt_addr)
{
	uint8_t src = __bar_msg_dst_index_trans(src_type);
	uint8_t dst = __bar_msg_src_index_trans(dst_type);

	if (src == BAR_MSG_SRC_ERR || dst == BAR_MSG_DST_ERR)
		return 0;

	uint8_t chan_id = chan_id_tbl[dst][src];
	uint8_t subchan_id = 1 - subchan_id_tbl[dst][src];
	uint64_t recv_rep_addr;

	if (sync == BAR_CHAN_MSG_SYNC)
		recv_rep_addr = subchan_addr_cal(virt_addr, chan_id, subchan_id);
	else
		recv_rep_addr = subchan_addr_cal(virt_addr, chan_id, 1 - subchan_id);

	return recv_rep_addr;
}

static uint16_t __bar_chan_msg_header_check(struct bar_msg_header *msg_header)
{
	uint8_t module_id = 0;
	uint16_t len = 0;

	if (msg_header->valid != BAR_MSG_CHAN_USED) {
		PMD_MSG_LOG(ERR, "recv header ERR: valid label is not used.");
		return BAR_MSG_ERR_MODULE;
	}

	module_id = msg_header->module_id;
	if (module_id >= (uint8_t)BAR_MSG_MODULE_NUM) {
		PMD_MSG_LOG(ERR, "recv header ERR: invalid module_id: %u.", module_id);
		return BAR_MSG_ERR_MODULE;
	}

	len = msg_header->len;
	if (len > BAR_MSG_PAYLOAD_MAX_LEN) {
		PMD_MSG_LOG(ERR, "recv header ERR: invalid mesg len: %u.", len);
		return BAR_MSG_ERR_LEN;
	}
	if (msg_recv_func_tbl[msg_header->module_id] == NULL) {
		PMD_MSG_LOG(ERR, "recv header ERR: module:%s(%u) doesn't register",
				module_id_name(module_id), module_id);
		return BAR_MSG_ERR_MODULE_NOEXIST;
	}
	return BAR_MSG_OK;
}

static void __bar_msg_sync_msg_proc(uint64_t reply_addr, struct bar_msg_header *msg_header,
					uint8_t *reciver_buff, void *dev)
{
	uint8_t *reps_buffer = rte_malloc(NULL, BAR_MSG_PAYLOAD_MAX_LEN, 0);

	if (reps_buffer == NULL)
		return;

	zxdh_bar_chan_msg_recv_callback recv_func = msg_recv_func_tbl[msg_header->module_id];
	uint16_t reps_len = 0;

	recv_func(reciver_buff, msg_header->len, reps_buffer, &reps_len, dev);
	msg_header->ack = BAR_CHAN_MSG_ACK;
	msg_header->len = reps_len;
	__bar_chan_msg_header_set(reply_addr, msg_header);
	__bar_chan_msg_payload_set(reply_addr, reps_buffer, reps_len);
	__bar_chan_msg_valid_set(reply_addr, BAR_MSG_CHAN_USABLE);
	rte_free(reps_buffer);
}

static void __bar_msg_ack_async_msg_proc(struct bar_msg_header *msg_header, uint8_t *reciver_buff)
{
	struct seqid_item *reps_info = &g_seqid_ring.reps_info_tbl[msg_header->msg_id];

	if (reps_info->flag != REPS_INFO_FLAG_USED) {
		PMD_MSG_LOG(ERR, "msg_id: %u is released", msg_header->msg_id);
		return;
	}
	if (msg_header->len > reps_info->buffer_len - 4) {
		PMD_MSG_LOG(ERR, "reps_buf_len is %u, but reps_msg_len is %u",
				reps_info->buffer_len, msg_header->len + 4);
		goto free_id;
	}
	uint8_t *reps_buffer = (uint8_t *)reps_info->reps_addr;

	rte_memcpy(reps_buffer + 4, reciver_buff, msg_header->len);
	*(uint16_t *)(reps_buffer + 1) = msg_header->len;
	*(uint8_t *)(reps_info->reps_addr) = REPS_HEADER_REPLYED;

free_id:
	__bar_chan_msgid_free(msg_header->msg_id);
}

int zxdh_bar_irq_recv(uint8_t src, uint8_t dst, uint64_t virt_addr, void *dev)
{
	uint64_t recv_addr = recv_addr_get(src, dst, virt_addr);

	if (recv_addr == 0) {
		PMD_MSG_LOG(ERR, "invalid driver type(src:%u, dst:%u).", src, dst);
		return -1;
	}

	struct bar_msg_header msg_header  = {0};

	__bar_chan_msg_header_get(recv_addr, &msg_header);
	uint16_t ret = __bar_chan_msg_header_check(&msg_header);

	if (ret != BAR_MSG_OK) {
		PMD_MSG_LOG(ERR, "recv msg_head err, ret: %u.", ret);
		return -1;
	}
	uint8_t *recved_msg = rte_malloc(NULL, msg_header.len, 0);

	if (recved_msg == NULL) {
		PMD_MSG_LOG(ERR, "malloc temp buff failed.");
		return -1;
	}
	__bar_chan_msg_payload_get(recv_addr, recved_msg, msg_header.len);

	uint64_t reps_addr = reply_addr_get(msg_header.sync, src, dst, virt_addr);

	if (msg_header.sync == BAR_CHAN_MSG_SYNC) {
		__bar_msg_sync_msg_proc(reps_addr, &msg_header, recved_msg, dev);
		goto exit;
	}
	__bar_chan_msg_valid_set(recv_addr, BAR_MSG_CHAN_USABLE);
	if (msg_header.ack == BAR_CHAN_MSG_ACK) {
		__bar_msg_ack_async_msg_proc(&msg_header, recved_msg);
		goto exit;
	}

exit:
	rte_free(recved_msg);
	return BAR_MSG_OK;
}

int zxdh_bar_chan_msg_recv_register(uint8_t module_id, zxdh_bar_chan_msg_recv_callback callback)
{
	if (module_id >= (uint16_t)BAR_MSG_MODULE_NUM) {
		PMD_MSG_LOG(ERR, "register ERR: invalid module_id: %u.", module_id);
		return BAR_MSG_ERR_MODULE;
	}
	if (callback == NULL) {
		PMD_MSG_LOG(ERR, "register %s(%u) error: null callback.",
			module_id_name(module_id), module_id);
		return BAR_MEG_ERR_NULL_FUNC;
	}
	if (msg_recv_func_tbl[module_id] != NULL) {
		PMD_MSG_LOG(ERR, "register warning, event:%s(%u) already be registered.",
			module_id_name(module_id), module_id);
		return BAR_MSG_ERR_REPEAT_REGISTER;
	}
	msg_recv_func_tbl[module_id] = callback;
	PMD_MSG_LOG(DEBUG, "register module: %s(%u) success.",
			module_id_name(module_id), module_id);
	return BAR_MSG_OK;
}

int zxdh_bar_chan_msg_recv_unregister(uint8_t module_id)
{
	if (module_id >= (uint16_t)BAR_MSG_MODULE_NUM) {
		PMD_MSG_LOG(ERR, "unregister ERR: invalid module_id :%u.", module_id);
		return BAR_MSG_ERR_MODULE;
	}
	if (msg_recv_func_tbl[module_id] == NULL) {
		PMD_MSG_LOG(ERR, "unregister wanning, event: %s(%d) has already be unregistered.",
			module_id_name(module_id), module_id);
		return BAR_MSG_ERR_UNGISTER;
	}
	msg_recv_func_tbl[module_id] = NULL;
	PMD_MSG_LOG(DEBUG, "unregister module %s(%d) success.",
		module_id_name(module_id), module_id);
	return BAR_MSG_OK;
}

static int bar_get_sum(uint8_t *ptr, uint8_t len)
{
	uint64_t sum = 0;
	int idx;

	for (idx = 0; idx < len; idx++)
		sum += *(ptr + idx);

	return (uint16_t)sum;
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
		PMD_MSG_LOG(ERR,
			"send sync_msg failed. pcieid: 0x%x, ret: %d.\n", dev->pcie_id, ret);
		return ret;
	}
	struct tbl_msg_reps_header *tbl_reps =
		(struct tbl_msg_reps_header *)(recv_buf + REPS_HEADER_PAYLOAD_OFFSET);

	if (tbl_reps->check != TBL_MSG_PRO_SUCCESS) {
		PMD_MSG_LOG(ERR,
			"get resource_field failed. pcieid: 0x%x, ret: %d.\n", dev->pcie_id, ret);
		return ret;
	}
	*len = tbl_reps->len;
	rte_memcpy(res,
		(recv_buf + REPS_HEADER_PAYLOAD_OFFSET + sizeof(struct tbl_msg_reps_header)), *len);
	return ret;
}

int zxdh_get_res_panel_id(struct zxdh_res_para *in, uint8_t *panel_id)
{
	uint8_t reps = 0;
	uint16_t reps_len = 0;

	if (zxdh_get_res_info(in, TBL_FIELD_PNLID, &reps, &reps_len) != BAR_MSG_OK)
		return -1;

	*panel_id = reps;
	return BAR_MSG_OK;
}
int zxdh_get_res_hash_id(struct zxdh_res_para *in, uint8_t *hash_id)
{
	uint8_t reps = 0;
	uint16_t reps_len = 0;

	if (zxdh_get_res_info(in, TBL_FIELD_HASHID, &reps, &reps_len) != BAR_MSG_OK)
		return -1;

	*hash_id = reps;
	return BAR_MSG_OK;
}

int zxdh_bar_chan_enable(struct msix_para *_msix_para, uint16_t *vport)
{
	int ret = 0;
	uint16_t check_token = 0;
	uint16_t sum_res = 0;

	recv_addr_get(MSG_CHAN_END_RISC, MSG_CHAN_END_PF, 0x0);

	if (!_msix_para)
		return BAR_MSG_ERR_NULL;

	struct msix_msg msix_msg = {
		.pcie_id = _msix_para->pcie_id,
		.vector_risc = _msix_para->vector_risc,
		.vector_pfvf = _msix_para->vector_pfvf,
		.vector_mpf = _msix_para->vector_mpf,
	};
	struct zxdh_pci_bar_msg in = {
		.virt_addr = _msix_para->virt_addr,
		.payload_addr = &msix_msg,
		.payload_len = sizeof(msix_msg),
		.emec = 0,
		.src = _msix_para->driver_type,
		.dst = MSG_CHAN_END_RISC,
		.module_id = BAR_MODULE_MISX,
		.src_pcieid = _msix_para->pcie_id,
		.dst_pcieid = 0,
		.usr = 0,
	};

	struct bar_recv_msg recv_msg = {0};
	struct zxdh_msg_recviver_mem result = {
		.recv_buffer = &recv_msg,
		.buffer_len = sizeof(recv_msg),
	};

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);

	if (ret != BAR_MSG_OK)
		return -ret;

	check_token = recv_msg.msix_reps.check;
	sum_res = bar_get_sum((uint8_t *)&msix_msg, sizeof(msix_msg));

	if (check_token != sum_res) {
		PMD_MSG_LOG(ERR, "expect token: 0x%x, get token: 0x%x.\n", sum_res, check_token);
		return BAR_MSG_ERR_REPLY;
	}
	*vport = recv_msg.msix_reps.vport;

	return BAR_MSG_OK;
}

int zxdh_get_bar_offset(struct bar_offset_params *paras, struct bar_offset_res *res)
{
	uint16_t check_token = 0;
	uint16_t sum_res = 0;
	int ret = 0;

	if (!paras)
		return BAR_MSG_ERR_NULL;

	struct offset_get_msg send_msg = {
		.pcie_id = paras->pcie_id,
		.type = paras->type,
	};
	struct zxdh_pci_bar_msg in = {0};

	in.payload_addr = &send_msg;
	in.payload_len = sizeof(send_msg);
	in.virt_addr = paras->virt_addr;
	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.module_id = BAR_MODULE_OFFSET_GET;
	in.src_pcieid = paras->pcie_id;

	struct bar_recv_msg recv_msg = {0};
	struct zxdh_msg_recviver_mem result = {
		.recv_buffer = &recv_msg,
		.buffer_len = sizeof(recv_msg),
	};
	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret != BAR_MSG_OK)
		return -ret;

	check_token = recv_msg.offset_reps.check;
	sum_res = bar_get_sum((uint8_t *)&send_msg, sizeof(send_msg));

	if (check_token != sum_res) {
		PMD_MSG_LOG(ERR, "expect token: 0x%x, get token: 0x%x.\n", sum_res, check_token);
		return BAR_MSG_ERR_REPLY;
	}
	res->bar_offset = recv_msg.offset_reps.offset;
	res->bar_length = recv_msg.offset_reps.length;
	return BAR_MSG_OK;
}

int zxdh_msg_chan_init(void)
{
	g_dev_stat.dev_cnt++;
	if (g_dev_stat.is_res_init)
		return BAR_MSG_OK;

	pthread_spin_init(&chan_lock, 0);
	g_seqid_ring.cur_id = 0;
	pthread_spin_init(&g_seqid_ring.lock, 0);
	uint16_t seq_id;

	for (seq_id = 0; seq_id < BAR_SEQID_NUM_MAX; seq_id++) {
		struct seqid_item *reps_info = &(g_seqid_ring.reps_info_tbl[seq_id]);

		reps_info->id = seq_id;
		reps_info->flag = REPS_INFO_FLAG_USABLE;
	}
	g_dev_stat.is_res_init = true;
	return BAR_MSG_OK;
}

int zxdh_bar_msg_chan_exit(void)
{
	if (!g_dev_stat.is_res_init || (--g_dev_stat.dev_cnt > 0))
		return BAR_MSG_OK;

	g_dev_stat.is_res_init = false;
	PMD_MSG_LOG(DEBUG, "%s exit success!", __func__);
	return BAR_MSG_OK;
}
