/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef __RNP_HW_H__
#define __RNP_HW_H__

#include <rte_io.h>
#include <ethdev_driver.h>

#include "rnp_osdep.h"
#include "rnp_dma_regs.h"
#include "rnp_eth_regs.h"
#include "rnp_cfg.h"

static inline unsigned int rnp_rd_reg(volatile void *addr)
{
	unsigned int v = rte_read32(addr);

	return v;
}

static inline void rnp_wr_reg(volatile void *reg, int val)
{
	rte_write32_relaxed((val), (reg));
}

#define mbx_rd32(_hw, _off)		\
	rnp_rd_reg((uint8_t *)((_hw)->iobar4) + (_off))
#define mbx_wr32(_hw, _off, _val)	\
	rnp_wr_reg((uint8_t *)((_hw)->iobar4) + (_off), (_val))
#define rnp_io_rd(_base, _off)		\
	rnp_rd_reg((uint8_t *)(_base) + (_off))
#define rnp_io_wr(_base, _off, _val)	\
	rnp_wr_reg((uint8_t *)(_base) + (_off), (_val))
#define rnp_eth_rd(_hw, _off)		\
	rnp_rd_reg((uint8_t *)((_hw)->eth_base) + (_off))
#define rnp_eth_wr(_hw, _off, _val)	\
	rnp_wr_reg((uint8_t *)((_hw)->eth_base) + (_off), (_val))
#define rnp_dma_rd(_hw, _off)		\
	rnp_rd_reg((uint8_t *)((_hw)->dma_base) + (_off))
#define rnp_dma_wr(_hw, _off, _val)	\
	rnp_wr_reg((uint8_t *)((_hw)->dma_base) + (_off), (_val))
#define rnp_top_rd(_hw, _off)		\
	rnp_rd_reg((uint8_t *)((_hw)->comm_reg_base) + (_off))
#define rnp_top_wr(_hw, _off, _val)	\
	rnp_wr_reg((uint8_t *)((_hw)->comm_reg_base) + (_off), (_val))
#define RNP_MACADDR_UPDATE_LO(hw, hw_idx, val) \
	rnp_eth_wr(hw, RNP_RAL_BASE_ADDR(hw_idx), val)
#define RNP_MACADDR_UPDATE_HI(hw, hw_idx, val) \
	rnp_eth_wr(hw, RNP_RAH_BASE_ADDR(hw_idx), val)
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

struct rnp_eth_port;
struct rnp_mac_api {
	int32_t (*init_hw)(struct rnp_hw *hw);
	int32_t (*reset_hw)(struct rnp_hw *hw);
	/* MAC Address */
	int32_t (*get_mac_addr)(struct rnp_eth_port *port,
				uint8_t lane,
				uint8_t *macaddr);
	int32_t (*set_default_mac)(struct rnp_eth_port *port, uint8_t *mac);
	/* Receive Address Filter Table */
	int32_t (*set_rafb)(struct rnp_eth_port *port,
			    uint8_t *mac,
			    uint8_t vm_pool,
			    uint8_t index);
	int32_t (*clear_rafb)(struct rnp_eth_port *port,
			    uint8_t vm_pool,
			    uint8_t index);
};

struct rnp_mac_info {
	uint8_t assign_addr[RTE_ETHER_ADDR_LEN];
	uint8_t set_addr[RTE_ETHER_ADDR_LEN];
	struct rnp_mac_api ops;
} __rte_cache_aligned;

struct rnp_eth_adapter;
#define RNP_MAX_HW_PORT_PERR_PF (4)
struct rnp_hw {
	struct rnp_eth_adapter *back;
	void *iobar0;
	uint32_t iobar0_len;
	void *iobar4;
	uint32_t iobar4_len;
	void *link_sync;
	void *dma_base;
	void *eth_base;
	void *veb_base;
	void *mac_base[RNP_MAX_HW_PORT_PERR_PF];
	void *comm_reg_base;
	void *msix_base;
	/* === dma == */
	void *dev_version;
	void *dma_axi_en;
	void *dma_axi_st;

	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t function;
	uint16_t pf_vf_num;
	int pfvfnum;
	uint16_t max_vfs;

	bool ncsi_en;
	uint8_t ncsi_rar_entries;

	int sgmii_phy_id;
	int is_sgmii;
	u16 phy_type;
	uint8_t force_10g_1g_speed_ablity;
	uint8_t force_speed_stat;
#define FORCE_SPEED_STAT_DISABLED       (0)
#define FORCE_SPEED_STAT_1G             (1)
#define FORCE_SPEED_STAT_10G            (2)
	uint32_t speed;
	unsigned int axi_mhz;

	int fw_version;  /* Primary FW Version */
	uint32_t fw_uid; /* Subclass Fw Version */

	int nic_mode;
	unsigned char lane_mask;
	int lane_of_port[4];
	char phy_port_ids[4]; /* port id: for lane0~3: value: 0 ~ 7 */
	uint8_t max_port_num; /* Max Port Num This PF Have */

	void *cookie_pool;
	char cookie_p_name[RTE_MEMZONE_NAMESIZE];

	struct rnp_mac_info mac;
	struct rnp_mbx_info mbx;
	rte_spinlock_t fw_lock;
} __rte_cache_aligned;
#endif /* __RNP_H__*/
