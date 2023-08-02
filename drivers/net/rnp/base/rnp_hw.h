/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef __RNP_HW_H__
#define __RNP_HW_H__

#include <rte_io.h>
#include <ethdev_driver.h>

#include "rnp_osdep.h"

static inline unsigned int rnp_rd_reg(volatile void *addr)
{
	unsigned int v = rte_read32(addr);

	return v;
}

static inline void rnp_wr_reg(volatile void *reg, int val)
{
	rte_write32_relaxed((val), (reg));
}

#define mbx_rd32(hw, reg)	rnp_rd_reg((hw)->iobar4 + (reg))
#define mbx_wr32(hw, reg, val)	rnp_wr_reg((hw)->iobar4 + (reg), (val))

struct rnp_hw;
/* Mbx Operate info */
enum MBX_ID {
	MBX_PF = 0,
	MBX_VF,
	MBX_CM3CPU,
	MBX_FW = MBX_CM3CPU,
	MBX_VFCNT
};
struct rnp_mbx_api {
	void (*init_mbx)(struct rnp_hw *hw);
	int32_t (*read)(struct rnp_hw *hw,
			uint32_t *msg,
			uint16_t size,
			enum MBX_ID);
	int32_t (*write)(struct rnp_hw *hw,
			uint32_t *msg,
			uint16_t size,
			enum MBX_ID);
	int32_t (*read_posted)(struct rte_eth_dev *dev,
			uint32_t *msg,
			uint16_t size,
			enum MBX_ID);
	int32_t (*write_posted)(struct rte_eth_dev *dev,
			uint32_t *msg,
			uint16_t size,
			enum MBX_ID);
	int32_t (*check_for_msg)(struct rnp_hw *hw, enum MBX_ID);
	int32_t (*check_for_ack)(struct rnp_hw *hw, enum MBX_ID);
	int32_t (*check_for_rst)(struct rnp_hw *hw, enum MBX_ID);
	int32_t (*configure)(struct rnp_hw *hw, int nr_vec, bool enable);
};

struct rnp_mbx_stats {
	u32 msgs_tx;
	u32 msgs_rx;

	u32 acks;
	u32 reqs;
	u32 rsts;
};

struct rnp_mbx_info {
	struct rnp_mbx_api ops;
	uint32_t usec_delay;    /* retry interval delay time */
	uint32_t timeout;       /* retry ops timeout limit */
	uint16_t size;          /* data buffer size*/
	uint16_t vf_num;        /* Virtual Function num */
	uint16_t pf_num;        /* Physical Function num */
	uint16_t sriov_st;      /* Sriov state */
	bool irq_enabled;
	union {
		struct {
			unsigned short pf_req;
			unsigned short pf_ack;
		};
		struct {
			unsigned short cpu_req;
			unsigned short cpu_ack;
		};
	};
	unsigned short vf_req[64];
	unsigned short vf_ack[64];

	struct rnp_mbx_stats stats;

	rte_atomic16_t state;
} __rte_cache_aligned;

#define RNP_MAX_HW_PORT_PERR_PF (4)
struct rnp_hw {
	void *back;
	char *iobar0;
	uint32_t iobar0_len;
	char *iobar4;
	uint32_t iobar4_len;
	char *link_sync;
	char *dma_base;
	char *eth_base;
	char *veb_base;
	char *mac_base[RNP_MAX_HW_PORT_PERR_PF];
	char *msix_base;
	/* === dma == */
	char *dma_axi_en;
	char *dma_axi_st;

	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t function;
	uint16_t pf_vf_num;
	uint16_t max_vfs;
	void *cookie_pool;
	char cookie_p_name[RTE_MEMZONE_NAMESIZE];

	struct rnp_mbx_info mbx;
} __rte_cache_aligned;
#endif /* __RNP_H__*/
