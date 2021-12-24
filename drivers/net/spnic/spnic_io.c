/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_io.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ethdev_core.h>
#include <ethdev_driver.h>

#include "base/spnic_compat.h"
#include "base/spnic_cmd.h"
#include "base/spnic_wq.h"
#include "base/spnic_mgmt.h"
#include "base/spnic_cmdq.h"
#include "base/spnic_hwdev.h"
#include "base/spnic_hw_comm.h"
#include "base/spnic_nic_cfg.h"
#include "base/spnic_hw_cfg.h"
#include "spnic_io.h"
#include "spnic_tx.h"
#include "spnic_rx.h"
#include "spnic_ethdev.h"

#define SPNIC_DEAULT_TX_CI_PENDING_LIMIT	0
#define SPNIC_DEAULT_TX_CI_COALESCING_TIME	0
#define SPNIC_DEAULT_DROP_THD_ON		0xFFFF
#define SPNIC_DEAULT_DROP_THD_OFF		0

#define WQ_PREFETCH_MAX			4
#define WQ_PREFETCH_MIN			1
#define WQ_PREFETCH_THRESHOLD		256

#define SPNIC_Q_CTXT_MAX		31

enum spnic_qp_ctxt_type {
	SPNIC_QP_CTXT_TYPE_SQ,
	SPNIC_QP_CTXT_TYPE_RQ,
};

struct spnic_qp_ctxt_header {
	u16 num_queues;
	u16 queue_type;
	u16 start_qid;
	u16 rsvd;
};

struct spnic_sq_ctxt {
	u32 ci_pi;
	u32 drop_mode_sp;
	u32 wq_pfn_hi_owner;
	u32 wq_pfn_lo;

	u32 rsvd0;
	u32 pkt_drop_thd;
	u32 global_sq_id;
	u32 vlan_ceq_attr;

	u32 pref_cache;
	u32 pref_ci_owner;
	u32 pref_wq_pfn_hi_ci;
	u32 pref_wq_pfn_lo;

	u32 rsvd8;
	u32 rsvd9;
	u32 wq_block_pfn_hi;
	u32 wq_block_pfn_lo;
};

struct spnic_rq_ctxt {
	u32 ci_pi;
	u32 ceq_attr;
	u32 wq_pfn_hi_type_owner;
	u32 wq_pfn_lo;

	u32 rsvd[3];
	u32 cqe_sge_len;

	u32 pref_cache;
	u32 pref_ci_owner;
	u32 pref_wq_pfn_hi_ci;
	u32 pref_wq_pfn_lo;

	u32 pi_paddr_hi;
	u32 pi_paddr_lo;
	u32 wq_block_pfn_hi;
	u32 wq_block_pfn_lo;
};

struct spnic_sq_ctxt_block {
	struct spnic_qp_ctxt_header cmdq_hdr;
	struct spnic_sq_ctxt sq_ctxt[SPNIC_Q_CTXT_MAX];
};

struct spnic_rq_ctxt_block {
	struct spnic_qp_ctxt_header cmdq_hdr;
	struct spnic_rq_ctxt rq_ctxt[SPNIC_Q_CTXT_MAX];
};

struct spnic_clean_queue_ctxt {
	struct spnic_qp_ctxt_header cmdq_hdr;
	u32 rsvd;
};

#define SQ_CTXT_SIZE(num_sqs)	((u16)(sizeof(struct spnic_qp_ctxt_header) \
				+ (num_sqs) * sizeof(struct spnic_sq_ctxt)))

#define RQ_CTXT_SIZE(num_rqs)	((u16)(sizeof(struct spnic_qp_ctxt_header) \
				+ (num_rqs) * sizeof(struct spnic_rq_ctxt)))

#define CI_IDX_HIGH_SHIFH				12

#define CI_HIGN_IDX(val)		((val) >> CI_IDX_HIGH_SHIFH)

#define SQ_CTXT_PI_IDX_SHIFT				0
#define SQ_CTXT_CI_IDX_SHIFT				16

#define SQ_CTXT_PI_IDX_MASK				0xFFFFU
#define SQ_CTXT_CI_IDX_MASK				0xFFFFU

#define SQ_CTXT_CI_PI_SET(val, member)			(((val) & \
					SQ_CTXT_##member##_MASK) \
					<< SQ_CTXT_##member##_SHIFT)

#define SQ_CTXT_MODE_SP_FLAG_SHIFT			0
#define SQ_CTXT_MODE_PKT_DROP_SHIFT			1

#define SQ_CTXT_MODE_SP_FLAG_MASK			0x1U
#define SQ_CTXT_MODE_PKT_DROP_MASK			0x1U

#define SQ_CTXT_MODE_SET(val, member)	(((val) & \
					SQ_CTXT_MODE_##member##_MASK) \
					<< SQ_CTXT_MODE_##member##_SHIFT)

#define SQ_CTXT_WQ_PAGE_HI_PFN_SHIFT			0
#define SQ_CTXT_WQ_PAGE_OWNER_SHIFT			23

#define SQ_CTXT_WQ_PAGE_HI_PFN_MASK			0xFFFFFU
#define SQ_CTXT_WQ_PAGE_OWNER_MASK			0x1U

#define SQ_CTXT_WQ_PAGE_SET(val, member)		(((val) & \
					SQ_CTXT_WQ_PAGE_##member##_MASK) \
					<< SQ_CTXT_WQ_PAGE_##member##_SHIFT)

#define SQ_CTXT_PKT_DROP_THD_ON_SHIFT			0
#define SQ_CTXT_PKT_DROP_THD_OFF_SHIFT			16

#define SQ_CTXT_PKT_DROP_THD_ON_MASK			0xFFFFU
#define SQ_CTXT_PKT_DROP_THD_OFF_MASK			0xFFFFU

#define SQ_CTXT_PKT_DROP_THD_SET(val, member)		(((val) & \
					SQ_CTXT_PKT_DROP_##member##_MASK) \
					<< SQ_CTXT_PKT_DROP_##member##_SHIFT)

#define SQ_CTXT_GLOBAL_SQ_ID_SHIFT			0

#define SQ_CTXT_GLOBAL_SQ_ID_MASK			0x1FFFU

#define SQ_CTXT_GLOBAL_QUEUE_ID_SET(val, member)	(((val) & \
					SQ_CTXT_##member##_MASK) \
					<< SQ_CTXT_##member##_SHIFT)


#define SQ_CTXT_VLAN_TAG_SHIFT				0
#define SQ_CTXT_VLAN_TYPE_SEL_SHIFT			16
#define SQ_CTXT_VLAN_INSERT_MODE_SHIFT			19
#define SQ_CTXT_VLAN_CEQ_EN_SHIFT			23

#define SQ_CTXT_VLAN_TAG_MASK				0xFFFFU
#define SQ_CTXT_VLAN_TYPE_SEL_MASK			0x7U
#define SQ_CTXT_VLAN_INSERT_MODE_MASK			0x3U
#define SQ_CTXT_VLAN_CEQ_EN_MASK			0x1U

#define SQ_CTXT_VLAN_CEQ_SET(val, member)		(((val) & \
					SQ_CTXT_VLAN_##member##_MASK) \
					<< SQ_CTXT_VLAN_##member##_SHIFT)

#define SQ_CTXT_PREF_CACHE_THRESHOLD_SHIFT		0
#define SQ_CTXT_PREF_CACHE_MAX_SHIFT			14
#define SQ_CTXT_PREF_CACHE_MIN_SHIFT			25

#define SQ_CTXT_PREF_CACHE_THRESHOLD_MASK		0x3FFFU
#define SQ_CTXT_PREF_CACHE_MAX_MASK			0x7FFU
#define SQ_CTXT_PREF_CACHE_MIN_MASK			0x7FU

#define SQ_CTXT_PREF_CI_HI_SHIFT			0
#define SQ_CTXT_PREF_OWNER_SHIFT			4

#define SQ_CTXT_PREF_CI_HI_MASK				0xFU
#define SQ_CTXT_PREF_OWNER_MASK				0x1U

#define SQ_CTXT_PREF_WQ_PFN_HI_SHIFT			0
#define SQ_CTXT_PREF_CI_LOW_SHIFT			20

#define SQ_CTXT_PREF_WQ_PFN_HI_MASK			0xFFFFFU
#define SQ_CTXT_PREF_CI_LOW_MASK			0xFFFU

#define SQ_CTXT_PREF_SET(val, member)			(((val) & \
					SQ_CTXT_PREF_##member##_MASK) \
					<< SQ_CTXT_PREF_##member##_SHIFT)

#define SQ_CTXT_WQ_BLOCK_PFN_HI_SHIFT			0

#define SQ_CTXT_WQ_BLOCK_PFN_HI_MASK			0x7FFFFFU

#define SQ_CTXT_WQ_BLOCK_SET(val, member)		(((val) & \
					SQ_CTXT_WQ_BLOCK_##member##_MASK) \
					<< SQ_CTXT_WQ_BLOCK_##member##_SHIFT)

#define RQ_CTXT_PI_IDX_SHIFT				0
#define RQ_CTXT_CI_IDX_SHIFT				16

#define RQ_CTXT_PI_IDX_MASK				0xFFFFU
#define RQ_CTXT_CI_IDX_MASK				0xFFFFU

#define RQ_CTXT_CI_PI_SET(val, member)			(((val) & \
					RQ_CTXT_##member##_MASK) \
					<< RQ_CTXT_##member##_SHIFT)

#define RQ_CTXT_CEQ_ATTR_INTR_SHIFT			21
#define RQ_CTXT_CEQ_ATTR_INTR_ARM_SHIFT			30
#define RQ_CTXT_CEQ_ATTR_EN_SHIFT			31

#define RQ_CTXT_CEQ_ATTR_INTR_MASK			0x3FFU
#define RQ_CTXT_CEQ_ATTR_INTR_ARM_MASK			0x1U
#define RQ_CTXT_CEQ_ATTR_EN_MASK			0x1U

#define RQ_CTXT_CEQ_ATTR_SET(val, member)		(((val) & \
					RQ_CTXT_CEQ_ATTR_##member##_MASK) \
					<< RQ_CTXT_CEQ_ATTR_##member##_SHIFT)

#define RQ_CTXT_WQ_PAGE_HI_PFN_SHIFT			0
#define RQ_CTXT_WQ_PAGE_WQE_TYPE_SHIFT			28
#define RQ_CTXT_WQ_PAGE_OWNER_SHIFT			31

#define RQ_CTXT_WQ_PAGE_HI_PFN_MASK			0xFFFFFU
#define RQ_CTXT_WQ_PAGE_WQE_TYPE_MASK			0x3U
#define RQ_CTXT_WQ_PAGE_OWNER_MASK			0x1U

#define RQ_CTXT_WQ_PAGE_SET(val, member)		(((val) & \
					RQ_CTXT_WQ_PAGE_##member##_MASK) << \
					RQ_CTXT_WQ_PAGE_##member##_SHIFT)

#define RQ_CTXT_CQE_LEN_SHIFT				28

#define RQ_CTXT_CQE_LEN_MASK				0x3U

#define RQ_CTXT_CQE_LEN_SET(val, member)		(((val) & \
					RQ_CTXT_##member##_MASK) << \
					RQ_CTXT_##member##_SHIFT)

#define RQ_CTXT_PREF_CACHE_THRESHOLD_SHIFT		0
#define RQ_CTXT_PREF_CACHE_MAX_SHIFT			14
#define RQ_CTXT_PREF_CACHE_MIN_SHIFT			25

#define RQ_CTXT_PREF_CACHE_THRESHOLD_MASK		0x3FFFU
#define RQ_CTXT_PREF_CACHE_MAX_MASK			0x7FFU
#define RQ_CTXT_PREF_CACHE_MIN_MASK			0x7FU

#define RQ_CTXT_PREF_CI_HI_SHIFT			0
#define RQ_CTXT_PREF_OWNER_SHIFT			4

#define RQ_CTXT_PREF_CI_HI_MASK				0xFU
#define RQ_CTXT_PREF_OWNER_MASK				0x1U

#define RQ_CTXT_PREF_WQ_PFN_HI_SHIFT			0
#define RQ_CTXT_PREF_CI_LOW_SHIFT			20

#define RQ_CTXT_PREF_WQ_PFN_HI_MASK			0xFFFFFU
#define RQ_CTXT_PREF_CI_LOW_MASK			0xFFFU

#define RQ_CTXT_PREF_SET(val, member)			(((val) & \
					RQ_CTXT_PREF_##member##_MASK) << \
					RQ_CTXT_PREF_##member##_SHIFT)

#define RQ_CTXT_WQ_BLOCK_PFN_HI_SHIFT			0

#define RQ_CTXT_WQ_BLOCK_PFN_HI_MASK			0x7FFFFFU

#define RQ_CTXT_WQ_BLOCK_SET(val, member)		(((val) & \
					RQ_CTXT_WQ_BLOCK_##member##_MASK) << \
					RQ_CTXT_WQ_BLOCK_##member##_SHIFT)

#define SIZE_16BYTES(size)		(RTE_ALIGN((size), 16) >> 4)

#define	WQ_PAGE_PFN_SHIFT				12
#define	WQ_BLOCK_PFN_SHIFT				9

#define WQ_PAGE_PFN(page_addr)		((page_addr) >> WQ_PAGE_PFN_SHIFT)
#define WQ_BLOCK_PFN(page_addr)		((page_addr) >> WQ_BLOCK_PFN_SHIFT)

static void
spnic_qp_prepare_cmdq_header(struct spnic_qp_ctxt_header *qp_ctxt_hdr,
			     enum spnic_qp_ctxt_type ctxt_type,
			     u16 num_queues, u16 q_id)
{
	qp_ctxt_hdr->queue_type = ctxt_type;
	qp_ctxt_hdr->num_queues = num_queues;
	qp_ctxt_hdr->start_qid = q_id;
	qp_ctxt_hdr->rsvd = 0;

	spnic_cpu_to_be32(qp_ctxt_hdr, sizeof(*qp_ctxt_hdr));
}

static void spnic_sq_prepare_ctxt(struct spnic_txq *sq, u16 sq_id,
				  struct spnic_sq_ctxt *sq_ctxt)
{
	u64 wq_page_addr;
	u64 wq_page_pfn, wq_block_pfn;
	u32 wq_page_pfn_hi, wq_page_pfn_lo;
	u32 wq_block_pfn_hi, wq_block_pfn_lo;
	u16 pi_start, ci_start;

	ci_start = sq->cons_idx & sq->q_mask;
	pi_start = sq->prod_idx & sq->q_mask;

	/* Read the first page from hardware table */
	wq_page_addr = sq->queue_buf_paddr;

	wq_page_pfn = WQ_PAGE_PFN(wq_page_addr);
	wq_page_pfn_hi = upper_32_bits(wq_page_pfn);
	wq_page_pfn_lo = lower_32_bits(wq_page_pfn);

	/* Use 0-level CLA */
	wq_block_pfn = WQ_BLOCK_PFN(wq_page_addr);
	wq_block_pfn_hi = upper_32_bits(wq_block_pfn);
	wq_block_pfn_lo = lower_32_bits(wq_block_pfn);

	sq_ctxt->ci_pi = SQ_CTXT_CI_PI_SET(ci_start, CI_IDX) |
			 SQ_CTXT_CI_PI_SET(pi_start, PI_IDX);

	sq_ctxt->drop_mode_sp = SQ_CTXT_MODE_SET(0, SP_FLAG) |
				SQ_CTXT_MODE_SET(0, PKT_DROP);

	sq_ctxt->wq_pfn_hi_owner = SQ_CTXT_WQ_PAGE_SET(wq_page_pfn_hi, HI_PFN) |
				   SQ_CTXT_WQ_PAGE_SET(1, OWNER);

	sq_ctxt->wq_pfn_lo = wq_page_pfn_lo;

	sq_ctxt->pkt_drop_thd =
		SQ_CTXT_PKT_DROP_THD_SET(SPNIC_DEAULT_DROP_THD_ON, THD_ON) |
		SQ_CTXT_PKT_DROP_THD_SET(SPNIC_DEAULT_DROP_THD_OFF, THD_OFF);

	sq_ctxt->global_sq_id =
		SQ_CTXT_GLOBAL_QUEUE_ID_SET(sq_id, GLOBAL_SQ_ID);

	/* Insert c-vlan in default */
	sq_ctxt->vlan_ceq_attr = SQ_CTXT_VLAN_CEQ_SET(0, CEQ_EN) |
				 SQ_CTXT_VLAN_CEQ_SET(1, INSERT_MODE);

	sq_ctxt->rsvd0 = 0;

	sq_ctxt->pref_cache = SQ_CTXT_PREF_SET(WQ_PREFETCH_MIN, CACHE_MIN) |
			      SQ_CTXT_PREF_SET(WQ_PREFETCH_MAX, CACHE_MAX) |
			      SQ_CTXT_PREF_SET(WQ_PREFETCH_THRESHOLD,
					       CACHE_THRESHOLD);

	sq_ctxt->pref_ci_owner =
		SQ_CTXT_PREF_SET(CI_HIGN_IDX(ci_start), CI_HI) |
		SQ_CTXT_PREF_SET(1, OWNER);

	sq_ctxt->pref_wq_pfn_hi_ci =
		SQ_CTXT_PREF_SET(ci_start, CI_LOW) |
		SQ_CTXT_PREF_SET(wq_page_pfn_hi, WQ_PFN_HI);

	sq_ctxt->pref_wq_pfn_lo = wq_page_pfn_lo;

	sq_ctxt->wq_block_pfn_hi =
		SQ_CTXT_WQ_BLOCK_SET(wq_block_pfn_hi, PFN_HI);

	sq_ctxt->wq_block_pfn_lo = wq_block_pfn_lo;

	spnic_cpu_to_be32(sq_ctxt, sizeof(*sq_ctxt));
}

static void spnic_rq_prepare_ctxt(struct spnic_rxq *rq,
				  struct spnic_rq_ctxt *rq_ctxt)
{
	u64 wq_page_addr;
	u64 wq_page_pfn, wq_block_pfn;
	u32 wq_page_pfn_hi, wq_page_pfn_lo;
	u32 wq_block_pfn_hi, wq_block_pfn_lo;
	u16 pi_start, ci_start;
	u16 wqe_type = rq->wqebb_shift - SPNIC_RQ_WQEBB_SHIFT;
	u8 intr_disable;

	/* RQ depth is in unit of 8 Bytes */
	ci_start = (u16)((rq->cons_idx & rq->q_mask) << wqe_type);
	pi_start = (u16)((rq->prod_idx & rq->q_mask) << wqe_type);

	/* Read the first page from hardware table */
	wq_page_addr = rq->queue_buf_paddr;

	wq_page_pfn = WQ_PAGE_PFN(wq_page_addr);
	wq_page_pfn_hi = upper_32_bits(wq_page_pfn);
	wq_page_pfn_lo = lower_32_bits(wq_page_pfn);

	/* Use 0-level CLA */
	wq_block_pfn = WQ_BLOCK_PFN(wq_page_addr);

	wq_block_pfn_hi = upper_32_bits(wq_block_pfn);
	wq_block_pfn_lo = lower_32_bits(wq_block_pfn);

	rq_ctxt->ci_pi = RQ_CTXT_CI_PI_SET(ci_start, CI_IDX) |
			 RQ_CTXT_CI_PI_SET(pi_start, PI_IDX);

	intr_disable = rq->dp_intr_en ? 0 : 1;
	rq_ctxt->ceq_attr = RQ_CTXT_CEQ_ATTR_SET(intr_disable, EN) |
			    RQ_CTXT_CEQ_ATTR_SET(0, INTR_ARM) |
			    RQ_CTXT_CEQ_ATTR_SET(rq->msix_entry_idx, INTR);

	/* Use 32Byte WQE with SGE for CQE in default */
	rq_ctxt->wq_pfn_hi_type_owner =
		RQ_CTXT_WQ_PAGE_SET(wq_page_pfn_hi, HI_PFN) |
		RQ_CTXT_WQ_PAGE_SET(1, OWNER);

	switch (wqe_type) {
	case SPNIC_EXTEND_RQ_WQE:
		/* Use 32Byte WQE with SGE for CQE */
		rq_ctxt->wq_pfn_hi_type_owner |=
			RQ_CTXT_WQ_PAGE_SET(0, WQE_TYPE);
		break;
	case SPNIC_NORMAL_RQ_WQE:
		/* Use 16Byte WQE with 32Bytes SGE for CQE */
		rq_ctxt->wq_pfn_hi_type_owner |=
			RQ_CTXT_WQ_PAGE_SET(2, WQE_TYPE);
		rq_ctxt->cqe_sge_len = RQ_CTXT_CQE_LEN_SET(1, CQE_LEN);
		break;
	default:
		PMD_DRV_LOG(INFO, "Invalid rq wqe type: %u", wqe_type);
	}

	rq_ctxt->wq_pfn_lo = wq_page_pfn_lo;

	rq_ctxt->pref_cache =
		RQ_CTXT_PREF_SET(WQ_PREFETCH_MIN, CACHE_MIN) |
		RQ_CTXT_PREF_SET(WQ_PREFETCH_MAX, CACHE_MAX) |
		RQ_CTXT_PREF_SET(WQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);

	rq_ctxt->pref_ci_owner =
		RQ_CTXT_PREF_SET(CI_HIGN_IDX(ci_start), CI_HI) |
		RQ_CTXT_PREF_SET(1, OWNER);

	rq_ctxt->pref_wq_pfn_hi_ci =
		RQ_CTXT_PREF_SET(wq_page_pfn_hi, WQ_PFN_HI) |
		RQ_CTXT_PREF_SET(ci_start, CI_LOW);

	rq_ctxt->pref_wq_pfn_lo = wq_page_pfn_lo;

	rq_ctxt->pi_paddr_hi = upper_32_bits(rq->pi_dma_addr);
	rq_ctxt->pi_paddr_lo = lower_32_bits(rq->pi_dma_addr);

	rq_ctxt->wq_block_pfn_hi =
		RQ_CTXT_WQ_BLOCK_SET(wq_block_pfn_hi, PFN_HI);

	rq_ctxt->wq_block_pfn_lo = wq_block_pfn_lo;

	spnic_cpu_to_be32(rq_ctxt, sizeof(*rq_ctxt));
}

static int init_sq_ctxts(struct spnic_nic_dev *nic_dev)
{
	struct spnic_sq_ctxt_block *sq_ctxt_block = NULL;
	struct spnic_sq_ctxt *sq_ctxt = NULL;
	struct spnic_cmd_buf *cmd_buf = NULL;
	struct spnic_txq *sq = NULL;
	u64 out_param = 0;
	u16 q_id, curr_id, max_ctxts, i;
	int err = 0;

	cmd_buf = spnic_alloc_cmd_buf(nic_dev->hwdev);
	if (!cmd_buf) {
		PMD_DRV_LOG(ERR, "Allocate cmd buf for sq ctx failed");
		return -ENOMEM;
	}

	q_id = 0;
	while (q_id < nic_dev->num_sqs) {
		sq_ctxt_block = cmd_buf->buf;
		sq_ctxt = sq_ctxt_block->sq_ctxt;

		max_ctxts = (nic_dev->num_sqs - q_id) > SPNIC_Q_CTXT_MAX ?
			     SPNIC_Q_CTXT_MAX : (nic_dev->num_sqs - q_id);

		spnic_qp_prepare_cmdq_header(&sq_ctxt_block->cmdq_hdr,
					      SPNIC_QP_CTXT_TYPE_SQ,
					      max_ctxts, q_id);

		for (i = 0; i < max_ctxts; i++) {
			curr_id = q_id + i;
			sq = nic_dev->txqs[curr_id];
			spnic_sq_prepare_ctxt(sq, curr_id, &sq_ctxt[i]);
		}

		cmd_buf->size = SQ_CTXT_SIZE(max_ctxts);
		err = spnic_cmdq_direct_resp(nic_dev->hwdev, SPNIC_MOD_L2NIC,
					      SPNIC_UCODE_CMD_MODIFY_QUEUE_CTX,
					      cmd_buf, &out_param, 0);
		if (err || out_param != 0) {
			PMD_DRV_LOG(ERR, "Set SQ ctxts failed, "
				    "err: %d, out_param: %" PRIu64 "",
				    err, out_param);

			err = -EFAULT;
			break;
		}

		q_id += max_ctxts;
	}

	spnic_free_cmd_buf(cmd_buf);
	return err;
}

static int init_rq_ctxts(struct spnic_nic_dev *nic_dev)
{
	struct spnic_rq_ctxt_block *rq_ctxt_block = NULL;
	struct spnic_rq_ctxt *rq_ctxt = NULL;
	struct spnic_cmd_buf *cmd_buf = NULL;
	struct spnic_rxq *rq = NULL;
	u64 out_param = 0;
	u16 q_id, curr_id, max_ctxts, i;
	int err = 0;

	cmd_buf = spnic_alloc_cmd_buf(nic_dev->hwdev);
	if (!cmd_buf) {
		PMD_DRV_LOG(ERR, "Allocate cmd buf for rq ctx failed");
		return -ENOMEM;
	}

	q_id = 0;
	while (q_id < nic_dev->num_rqs) {
		rq_ctxt_block = cmd_buf->buf;
		rq_ctxt = rq_ctxt_block->rq_ctxt;

		max_ctxts = (nic_dev->num_rqs - q_id) > SPNIC_Q_CTXT_MAX ?
			    SPNIC_Q_CTXT_MAX : (nic_dev->num_rqs - q_id);

		spnic_qp_prepare_cmdq_header(&rq_ctxt_block->cmdq_hdr,
					      SPNIC_QP_CTXT_TYPE_RQ, max_ctxts,
					      q_id);

		for (i = 0; i < max_ctxts; i++) {
			curr_id = q_id + i;
			rq = nic_dev->rxqs[curr_id];

			spnic_rq_prepare_ctxt(rq, &rq_ctxt[i]);
		}

		cmd_buf->size = RQ_CTXT_SIZE(max_ctxts);
		err = spnic_cmdq_direct_resp(nic_dev->hwdev, SPNIC_MOD_L2NIC,
					      SPNIC_UCODE_CMD_MODIFY_QUEUE_CTX,
					      cmd_buf, &out_param, 0);
		if (err || out_param != 0) {
			PMD_DRV_LOG(ERR, "Set RQ ctxts failed, "
				    "err: %d, out_param: %" PRIu64 "",
				    err, out_param);
			err = -EFAULT;
			break;
		}

		q_id += max_ctxts;
	}

	spnic_free_cmd_buf(cmd_buf);
	return err;
}

static int clean_queue_offload_ctxt(struct spnic_nic_dev *nic_dev,
				    enum spnic_qp_ctxt_type ctxt_type)
{
	struct spnic_clean_queue_ctxt *ctxt_block = NULL;
	struct spnic_cmd_buf *cmd_buf;
	u64 out_param = 0;
	int err;

	cmd_buf = spnic_alloc_cmd_buf(nic_dev->hwdev);
	if (!cmd_buf) {
		PMD_DRV_LOG(ERR, "Allocate cmd buf for LRO/TSO space failed");
		return -ENOMEM;
	}

	ctxt_block = cmd_buf->buf;
	ctxt_block->cmdq_hdr.num_queues = nic_dev->max_sqs;
	ctxt_block->cmdq_hdr.queue_type = ctxt_type;
	ctxt_block->cmdq_hdr.start_qid = 0;

	spnic_cpu_to_be32(ctxt_block, sizeof(*ctxt_block));

	cmd_buf->size = sizeof(*ctxt_block);

	err = spnic_cmdq_direct_resp(nic_dev->hwdev, SPNIC_MOD_L2NIC,
				      SPNIC_UCODE_CMD_CLEAN_QUEUE_CONTEXT,
				      cmd_buf, &out_param, 0);
	if ((err) || (out_param)) {
		PMD_DRV_LOG(ERR, "Clean queue offload ctxts failed, "
			    "err: %d, out_param: %" PRIu64 "", err, out_param);
		err = -EFAULT;
	}

	spnic_free_cmd_buf(cmd_buf);
	return err;
}

static int clean_qp_offload_ctxt(struct spnic_nic_dev *nic_dev)
{
	/* Clean LRO/TSO context space */
	return (clean_queue_offload_ctxt(nic_dev, SPNIC_QP_CTXT_TYPE_SQ) ||
		clean_queue_offload_ctxt(nic_dev, SPNIC_QP_CTXT_TYPE_RQ));
}

void spnic_get_func_rx_buf_size(void *dev)
{
	struct spnic_nic_dev *nic_dev = (struct spnic_nic_dev *)dev;
	struct spnic_rxq *rxq = NULL;
	u16 q_id;
	u16 buf_size = 0;

	for (q_id = 0; q_id < nic_dev->num_rqs; q_id++) {
		rxq = nic_dev->rxqs[q_id];

		if (rxq == NULL)
			continue;

		if (q_id == 0)
			buf_size = rxq->buf_len;

		buf_size = buf_size > rxq->buf_len ? rxq->buf_len : buf_size;
	}

	nic_dev->rx_buff_len = buf_size;
}

/* Init qps ctxt and set sq ci attr and arm all sq */
int spnic_init_qp_ctxts(void *dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	struct spnic_hwdev *hwdev = NULL;
	struct spnic_sq_attr sq_attr;
	u32 rq_depth;
	u16 q_id;
	int err;

	if (!dev)
		return -EINVAL;

	nic_dev = (struct spnic_nic_dev *)dev;
	hwdev = nic_dev->hwdev;

	err = init_sq_ctxts(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init SQ ctxts failed");
		return err;
	}

	err = init_rq_ctxts(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init RQ ctxts failed");
		return err;
	}

	err = clean_qp_offload_ctxt(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Clean qp offload ctxts failed");
		return err;
	}

	rq_depth = ((u32)nic_dev->rxqs[0]->q_depth) <<
		   nic_dev->rxqs[0]->wqe_type;
	err = spnic_set_root_ctxt(hwdev, rq_depth, nic_dev->txqs[0]->q_depth,
				   nic_dev->rx_buff_len);
	if (err) {
		PMD_DRV_LOG(ERR, "Set root context failed");
		return err;
	}

	for (q_id = 0; q_id < nic_dev->num_sqs; q_id++) {
		sq_attr.ci_dma_base = nic_dev->txqs[q_id]->ci_dma_base >> 2;
		sq_attr.pending_limit = SPNIC_DEAULT_TX_CI_PENDING_LIMIT;
		sq_attr.coalescing_time = SPNIC_DEAULT_TX_CI_COALESCING_TIME;
		sq_attr.intr_en = 0;
		sq_attr.intr_idx = 0; /* Tx doesn't need intr */
		sq_attr.l2nic_sqn = q_id;
		sq_attr.dma_attr_off = 0;
		err = spnic_set_ci_table(hwdev, &sq_attr);
		if (err) {
			PMD_DRV_LOG(ERR, "Set ci table failed");
			goto set_cons_idx_table_err;
		}
	}

	return 0;

set_cons_idx_table_err:
	spnic_clean_root_ctxt(hwdev);
	return err;
}

void spnic_free_qp_ctxts(void *hwdev)
{
	if (!hwdev)
		return;

	spnic_clean_root_ctxt(hwdev);
}

void spnic_update_driver_feature(void *dev, u64 s_feature)
{
	struct spnic_nic_dev *nic_dev = NULL;

	if (!dev)
		return;

	nic_dev = (struct spnic_nic_dev *)dev;
	nic_dev->feature_cap = s_feature;

	PMD_DRV_LOG(INFO, "Update nic feature to %" PRIu64 "\n",
		    nic_dev->feature_cap);
}

u64 spnic_get_driver_feature(void *dev)
{
	struct spnic_nic_dev *nic_dev = NULL;

	if (!dev)
		return -EINVAL;

	nic_dev = (struct spnic_nic_dev *)dev;

	return nic_dev->feature_cap;
}
