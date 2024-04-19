/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 Advanced Micro Devices, Inc.
 */

#ifndef _IONIC_CRYPTO_H_
#define _IONIC_CRYPTO_H_

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_dev.h>
#include <rte_cryptodev.h>
#include <cryptodev_pmd.h>
#include <rte_log.h>
#include <rte_bitmap.h>

#include "ionic_common.h"
#include "ionic_crypto_if.h"
#include "ionic_regs.h"

#define IOCPT_ADMINQ_LENGTH		16	/* must be a power of two */

#define IOCPT_CRYPTOQ_WAIT		10	/* 1s */

extern int iocpt_logtype;
#define RTE_LOGTYPE_IOCPT iocpt_logtype

#define IOCPT_PRINT(level, ...)						\
	RTE_LOG_LINE_PREFIX(level, IOCPT, "%s(): ", __func__, __VA_ARGS__)

#define IOCPT_PRINT_CALL() IOCPT_PRINT(DEBUG, " >>")

struct iocpt_qtype_info {
	uint8_t	 version;
	uint8_t	 supported;
	uint64_t features;
	uint16_t desc_sz;
	uint16_t comp_sz;
	uint16_t sg_desc_sz;
	uint16_t max_sg_elems;
	uint16_t sg_desc_stride;
};

#define IOCPT_Q_F_INITED	BIT(0)
#define IOCPT_Q_F_DEFERRED	BIT(1)
#define IOCPT_Q_F_SG		BIT(2)

#define Q_NEXT_TO_POST(_q, _n)	(((_q)->head_idx + (_n)) & ((_q)->size_mask))
#define Q_NEXT_TO_SRVC(_q, _n)	(((_q)->tail_idx + (_n)) & ((_q)->size_mask))

#define IOCPT_INFO_SZ(_q)	((_q)->num_segs * sizeof(void *))
#define IOCPT_INFO_IDX(_q, _i)	((_i) * (_q)->num_segs)
#define IOCPT_INFO_PTR(_q, _i)	(&(_q)->info[IOCPT_INFO_IDX((_q), _i)])

struct iocpt_queue {
	uint16_t num_descs;
	uint16_t num_segs;
	uint16_t head_idx;
	uint16_t tail_idx;
	uint16_t size_mask;
	uint8_t type;
	uint8_t hw_type;
	void *base;
	void *sg_base;
	struct ionic_doorbell __iomem *db;
	void **info;

	uint32_t index;
	uint32_t hw_index;
	rte_iova_t base_pa;
	rte_iova_t sg_base_pa;
};

struct iocpt_cq {
	uint16_t tail_idx;
	uint16_t num_descs;
	uint16_t size_mask;
	bool done_color;
	void *base;
	rte_iova_t base_pa;
};

#define IOCPT_COMMON_FIELDS				\
	struct iocpt_queue q;				\
	struct iocpt_cq cq;				\
	struct iocpt_dev *dev;				\
	const struct rte_memzone *base_z;		\
	void *base;					\
	rte_iova_t base_pa

struct iocpt_common_q {
	IOCPT_COMMON_FIELDS;
};

struct iocpt_admin_q {
	IOCPT_COMMON_FIELDS;

	uint16_t flags;
};

#define IOCPT_DEV_F_INITED		BIT(0)
#define IOCPT_DEV_F_UP			BIT(1)
#define IOCPT_DEV_F_FW_RESET		BIT(2)

/* Combined dev / LIF object */
struct iocpt_dev {
	const char *name;
	char fw_version[IOCPT_FWVERS_BUFLEN];
	struct iocpt_identity ident;

	void *bus_dev;
	struct rte_cryptodev *crypto_dev;

	union iocpt_dev_info_regs __iomem *dev_info;
	union iocpt_dev_cmd_regs __iomem *dev_cmd;

	struct ionic_doorbell __iomem *db_pages;
	struct ionic_intr __iomem *intr_ctrl;

	uint32_t max_qps;
	uint32_t max_sessions;
	uint16_t state;
	uint8_t driver_id;
	uint8_t socket_id;

	rte_spinlock_t adminq_lock;
	rte_spinlock_t adminq_service_lock;

	struct iocpt_admin_q *adminq;

	uint64_t features;
	uint32_t hw_features;

	uint32_t info_sz;
	struct iocpt_lif_info *info;
	rte_iova_t info_pa;
	const struct rte_memzone *info_z;

	struct iocpt_qtype_info qtype_info[IOCPT_QTYPE_MAX];
	uint8_t qtype_ver[IOCPT_QTYPE_MAX];

	struct rte_cryptodev_stats stats_base;
};

/** iocpt_admin_ctx - Admin command context.
 * @pending_work:	Flag that indicates a completion.
 * @cmd:		Admin command (64B) to be copied to the queue.
 * @comp:		Admin completion (16B) copied from the queue.
 */
struct iocpt_admin_ctx {
	bool pending_work;
	union iocpt_adminq_cmd cmd;
	union iocpt_adminq_comp comp;
};

int iocpt_dev_identify(struct iocpt_dev *dev);
int iocpt_dev_init(struct iocpt_dev *dev, rte_iova_t info_pa);
int iocpt_dev_adminq_init(struct iocpt_dev *dev);
void iocpt_dev_reset(struct iocpt_dev *dev);

int iocpt_adminq_post_wait(struct iocpt_dev *dev, struct iocpt_admin_ctx *ctx);

struct ionic_doorbell __iomem *iocpt_db_map(struct iocpt_dev *dev,
	struct iocpt_queue *q);

typedef bool (*iocpt_cq_cb)(struct iocpt_cq *cq, uint16_t cq_desc_index,
		void *cb_arg);
uint32_t iocpt_cq_service(struct iocpt_cq *cq, uint32_t work_to_do,
	iocpt_cq_cb cb, void *cb_arg);

static inline uint16_t
iocpt_q_space_avail(struct iocpt_queue *q)
{
	uint16_t avail = q->tail_idx;

	if (q->head_idx >= avail)
		avail += q->num_descs - q->head_idx - 1;
	else
		avail -= q->head_idx + 1;

	return avail;
}

static inline void
iocpt_q_flush(struct iocpt_queue *q)
{
	uint64_t val = IONIC_DBELL_QID(q->hw_index) | q->head_idx;

#if defined(RTE_LIBRTE_IONIC_PMD_BARRIER_ERRATA)
	/* On some devices the standard 'dmb' barrier is insufficient */
	asm volatile("dsb st" : : : "memory");
	rte_write64_relaxed(rte_cpu_to_le_64(val), q->db);
#else
	rte_write64(rte_cpu_to_le_64(val), q->db);
#endif
}

static inline bool
iocpt_is_embedded(void)
{
#if defined(RTE_LIBRTE_IONIC_PMD_EMBEDDED)
	return true;
#else
	return false;
#endif
}

#endif /* _IONIC_CRYPTO_H_ */
