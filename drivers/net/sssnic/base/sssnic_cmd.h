/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_CMD_H_
#define _SSSNIC_CMD_H_

#define SSSNIC_CMD_OPCODE_SET 1
#define SSSNIC_CMD_OPCODE_GET 0

enum sssnic_mgmt_cmd_id {
	SSSNIC_RESET_FUNC_CMD = 0,
	SSSNIC_SET_CTRLQ_CTX_CMD = 20,
	SSSNIC_SET_ROOT_CTX_CMD = 21,
	SSSNIC_PAGESIZE_CFG_CMD = 22,
	SSSNIC_MSIX_CTRL_CMD = 23,
	SSSNIC_SET_DMA_ATTR_CMD = 25,
	SSSNIC_GET_FW_VERSION_CMD = 60,
};

#define SSSNIC_GET_CAPABILITY_CMD 0

#define SSSNIC_MAC_ADDR_CMD_STATUS_IGNORED 0x4
enum sssnic_mac_addr_cmd_id {
	SSSNIC_GET_MAC_ADDR_CMD = 20,
	SSSNIC_ADD_MAC_ADDR_CMD,
	SSSNIC_DEL_MAC_ADDR_CMD,
	SSSNIC_UPDATE_MAC_ADDR_CMD,
};
enum sssnic_netif_cmd_id {
	SSSNIC_SET_NETIF_ENABLE_CMD = 6,
	SSSNIC_GET_NETIF_LINK_STATUS_CMD = 7,
	SSSNIC_GET_NETIF_MAC_STATS_CMD = 151,
	SSSNIC_CLEAR_NETIF_MAC_STATS_CMD = 152,
	SSSNIC_GET_NETIF_LINK_INFO_CMD = 153,
};

enum sssnic_port_cmd_id {
	SSSNIC_REGISTER_VF_PORT_CMD = 0,
	SSSNIC_SET_PORT_RXTX_SIZE_CMD = 5,
	SSSNIC_SET_PORT_ENABLE_CMD = 6,
	SSSNIC_SET_PORT_RX_MODE_CMD = 7,
	SSSNIC_SET_PORT_TX_CI_ATTR_CMD = 8,
	SSSNIC_GET_PORT_STATS_CMD = 9,
	SSSNIC_CLEAR_PORT_STATS_CMD = 10,

	SSSNIC_CLEAN_PORT_RES_CMD = 11,

	SSSNIC_PORT_LRO_CFG_CMD = 13,
	SSSNIC_PORT_LRO_TIMER_CMD = 14,
	SSSNIC_PORT_FEATURE_CMD = 15,

	SSSNIC_SET_PORT_VLAN_FILTER_CMD = 25,
	SSSNIC_ENABLE_PORT_VLAN_FILTER_CMD = 26,
	SSSNIC_ENABLE_PORT_VLAN_STRIP_CMD = 27,

	SSSNIC_PORT_FLOW_CTRL_CMD = 101,
};

enum sssnic_ctrlq_cmd_id {
	SSSNIC_SET_RXTXQ_CTX_CMD = 0,
	SSSNIC_RESET_OFFLOAD_CTX_CMD = 1,
	SSSNIC_SET_RSS_INDIR_TABLE_CMD = 4,
	SSSNIC_SET_RSS_KEY_CTRLQ_CMD = 5,
	SSSNIC_GET_RSS_INDIR_TABLE_CMD = 6,
	SSSNIC_FLUSH_RXQ_CMD = 10,
};

struct sssnic_cmd_common {
	uint8_t status;
	uint8_t version;
	uint8_t resvd[6];
};

struct sssnic_set_ctrlq_ctx_cmd {
	struct sssnic_cmd_common common;
	uint16_t func_id;
	/* CtrlQ ID, here always is 0 */
	uint8_t qid;
	uint8_t resvd[5];
	union {
		uint64_t data[2];
		struct {
			/* Page frame number*/
			uint64_t pfn : 52;
			uint64_t resvd0 : 4;
			/* Completion event queue ID*/
			uint64_t eq_id : 5;
			/* Interrupt enable indication */
			uint64_t informed : 1;
			/* Completion event queue enable indication */
			uint64_t eq_en : 1;
			/* Entries wrapped indication */
			uint64_t wrapped : 1;
			uint64_t block_pfn : 52;
			uint64_t start_ci : 12;
		};
	};
};

struct sssnic_dma_attr_set_cmd {
	struct sssnic_cmd_common common;
	uint16_t func_id;
	uint8_t idx;
	uint8_t st;
	uint8_t at;
	uint8_t ph;
	uint8_t no_snooping;
	uint8_t tph;
	uint32_t resvd0;
};

struct sssnic_func_reset_cmd {
	struct sssnic_cmd_common common;
	uint16_t func_id;
	uint16_t resvd[3];
	/* Mask of reource to be reset */
	uint64_t res_mask;
};

struct sssnic_root_ctx_cmd {
	struct sssnic_cmd_common common;
	uint16_t func_id;
	/* set ctrlq depth enable */
	uint8_t set_ctrlq_depth;
	/* real depth is 2^ctrlq_depth */
	uint8_t ctrlq_depth;
	uint16_t rx_buf;
	uint8_t lro_enable;
	uint8_t resvd0;
	uint16_t txq_depth;
	uint16_t rxq_depth;
	uint64_t resvd1;
};

struct sssnic_pagesize_cmd {
	struct sssnic_cmd_common common;
	uint16_t func_id;
	/* SSSNIC_CMD_OPCODE_xx */
	uint8_t opcode;
	/* real size is (2^pagesz)*4KB */
	uint8_t pagesz;
	uint32_t resvd0;
};

struct sssnic_msix_ctrl_cmd {
	struct sssnic_cmd_common common;
	uint16_t func_id;
	/* SSSNIC_CMD_OPCODE_xx */
	uint8_t opcode;
	uint8_t resvd0;
	/* MSIX index */
	uint16_t idx;
	uint8_t pending_count;
	uint8_t coalescing_timer;
	uint8_t resend_timer;
	uint8_t lli_timer;
	uint8_t lli_credit;
	uint8_t resvd1[5];
};

struct sssnic_capability_get_cmd {
	struct sssnic_cmd_common common;
	uint16_t function;
	uint16_t resvd0;
	uint8_t resvd1[3];
	uint8_t phy_port;
	uint32_t resvd2[16];
	uint16_t txq_max_id;
	uint16_t rxq_max_id;
	uint32_t resvd3[63];
};

struct sssnic_mac_addr_cmd {
	struct sssnic_cmd_common common;
	uint16_t function;
	uint16_t vlan;
	uint16_t resvd;
	uint8_t addr[6];
};

struct sssnic_mac_addr_update_cmd {
	struct sssnic_cmd_common common;
	uint16_t function;
	uint16_t vlan;
	uint16_t resvd0;
	uint8_t old_addr[6];
	uint16_t resvd1;
	uint8_t new_addr[6];
};
struct sssnic_netif_link_status_get_cmd {
	struct sssnic_cmd_common common;
	uint8_t port;
	uint8_t status;
	uint16_t rsvd;
};

struct sssnic_netif_link_info_get_cmd {
	struct sssnic_cmd_common common;
	uint8_t port;
	uint8_t resvd0[3];
	uint8_t type;
	uint8_t autoneg_capa;
	uint8_t autoneg;
	uint8_t duplex;
	uint8_t speed;
	uint8_t fec;
	uint8_t resvd1[18];
};

#define SSSNIC_SET_NETIF_ENABLE_CMD_FLAG_TX_EN 0x1
#define SSSNIC_SET_NETIF_ENABLE_CMD_FLAG_RX_EN 0x2
struct sssnic_netif_enable_set_cmd {
	struct sssnic_cmd_common common;
	uint16_t function;
	uint16_t resvd0;
	uint8_t flag;
	uint8_t resvd1[3];
};

struct sssnic_port_enable_set_cmd {
	struct sssnic_cmd_common common;
	uint16_t function;
	uint16_t resvd0;
	uint8_t state;
	uint8_t resvd1[3];
};

struct sssnic_rxq_flush_cmd {
	union {
		struct {
			uint16_t resvd0;
			uint16_t qid;
		};
		uint32_t u32;
	};
};

#endif /* _SSSNIC_CMD_H_ */
