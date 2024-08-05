/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 ZTE Corporation
 */

#ifndef __ZXDH_RAWDEV_H__
#define __ZXDH_RAWDEV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_rawdev.h>
#include <rte_spinlock.h>

extern int zxdh_gdma_rawdev_logtype;
#define RTE_LOGTYPE_ZXDH_GDMA                   zxdh_gdma_rawdev_logtype

#define ZXDH_PMD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, ZXDH_GDMA, \
		"%s() line %u: ", __func__ RTE_LOG_COMMA __LINE__, __VA_ARGS__)

#define ZXDH_GDMA_VENDORID                      0x1cf2
#define ZXDH_GDMA_DEVICEID                      0x8044

#define ZXDH_GDMA_TOTAL_CHAN_NUM                58
#define ZXDH_GDMA_QUEUE_SIZE                    16384
#define ZXDH_GDMA_RING_SIZE                     32768

enum zxdh_gdma_device_state {
	ZXDH_GDMA_DEV_RUNNING,
	ZXDH_GDMA_DEV_STOPPED
};

struct zxdh_gdma_buff_desc {
	uint SrcAddr_L;
	uint DstAddr_L;
	uint Xpara;
	uint ZY_para;
	uint ZY_SrcStep;
	uint ZY_DstStep;
	uint ExtAddr;
	uint LLI_Addr_L;
	uint LLI_Addr_H;
	uint ChCont;
	uint LLI_User;
	uint ErrAddr;
	uint Control;
	uint SrcAddr_H;
	uint DstAddr_H;
	uint Reserved;
};

struct zxdh_gdma_job {
	uint64_t src;
	uint64_t dest;
	uint len;
	uint flags;
	uint64_t cnxt;
	uint16_t status;
	uint16_t vq_id;
	void *usr_elem;
	uint8_t ep_id;
	uint8_t pf_id;
	uint16_t vf_id;
};

struct zxdh_gdma_queue {
	uint8_t   enable;
	uint8_t   is_txq;
	uint16_t  vq_id;
	uint16_t  queue_size;
	/* 0:GDMA needs to be configured through the APB interface */
	uint16_t  flag;
	uint      user;
	uint16_t  tc_cnt;
	rte_spinlock_t enqueue_lock;
	struct {
		uint16_t avail_idx;
		uint16_t last_avail_idx;
		rte_iova_t ring_mem;
		const struct rte_memzone *ring_mz;
		struct zxdh_gdma_buff_desc *desc;
	} ring;
	struct {
		uint16_t  free_cnt;
		uint16_t  deq_cnt;
		uint16_t  pend_cnt;
		uint16_t  enq_idx;
		uint16_t  deq_idx;
		uint16_t  used_idx;
		struct zxdh_gdma_job **job;
	} sw_ring;
};

struct zxdh_gdma_rawdev {
	struct rte_device *device;
	struct rte_rawdev *rawdev;
	uintptr_t base_addr;
	uint8_t queue_num; /* total queue num */
	uint8_t used_num;  /* used  queue num */
	enum zxdh_gdma_device_state device_state;
	struct zxdh_gdma_queue vqs[ZXDH_GDMA_TOTAL_CHAN_NUM];
};

struct zxdh_gdma_config {
	uint16_t max_hw_queues_per_core;
	uint16_t max_vqs;
	int fle_queue_pool_cnt;
};

struct zxdh_gdma_rbp {
	uint use_ultrashort:1;
	uint enable:1;
	uint dportid:3;
	uint dpfid:3;
	uint dvfid:8; /*using route by port for destination */
	uint drbp:1;
	uint sportid:3;
	uint spfid:3;
	uint svfid:8;
	uint srbp:1;
};

struct zxdh_gdma_queue_config {
	uint lcore_id;
	uint flags;
	struct zxdh_gdma_rbp *rbp;
};

struct zxdh_gdma_attr {
	uint16_t num_hw_queues;
};

static inline struct zxdh_gdma_rawdev *
zxdh_gdma_rawdev_get_priv(const struct rte_rawdev *rawdev)
{
	return rawdev->dev_private;
}

uint zxdh_gdma_read_reg(struct rte_rawdev *dev, uint16_t qidx, uint offset);
void zxdh_gdma_write_reg(struct rte_rawdev *dev, uint16_t qidx, uint offset, uint val);

#ifdef __cplusplus
}
#endif

#endif /* __ZXDH_RAWDEV_H__ */
