/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_API_H_
#define _SSSNIC_API_H_

struct sssnic_msix_attr {
	uint32_t lli_set;
	uint32_t coalescing_set;
	uint8_t lli_credit;
	uint8_t lli_timer;
	uint8_t pending_limit;
	uint8_t coalescing_timer;
	uint8_t resend_timer;
};

struct sssnic_capability {
	uint16_t max_num_txq;
	uint16_t max_num_rxq;
	uint8_t phy_port;
	uint8_t cos;
};

struct sssnic_netif_link_info {
	uint8_t status;
	uint8_t type;
	uint8_t autoneg_capa;
	uint8_t autoneg;
	uint8_t duplex;
	uint8_t speed;
	uint8_t fec;
};

struct sssnic_rxq_ctx {
	union {
		uint32_t dword0;
		struct {
			/* producer index of workq */
			uint32_t pi : 16;
			/* consumer index of workq */
			uint32_t ci : 16;
		};
	};

	union {
		uint32_t dword1;
		struct {
			uint32_t dw1_resvd0 : 21;
			uint32_t msix_id : 10;
			uint32_t intr_dis : 1;
		};
	};

	union {
		uint32_t dword2;
		struct {
			uint32_t wq_pfn_hi : 20;
			uint32_t dw2_resvd0 : 8;
			/* DPDK PMD always set to 2,
			 * represent 16 bytes workq entry
			 */
			uint32_t wqe_type : 2;
			uint32_t dw2_resvd1 : 1;
			/* DPDK PMD always set to 1 */
			uint32_t wq_owner : 1;
		};
	};

	union {
		uint32_t dword3;
		uint32_t wq_pfn_lo;
	};

	uint32_t dword4;
	uint32_t dword5;
	uint32_t dword6;

	union {
		uint32_t dword7;
		struct {
			uint32_t dw7_resvd0 : 28;
			/* PMD always set to 1, represent 32 bytes CQE*/
			uint32_t rxd_len : 2;
			uint32_t dw7_resvd1 : 2;
		};
	};

	union {
		uint32_t dword8;
		struct {
			uint32_t pre_cache_thd : 14;
			uint32_t pre_cache_max : 11;
			uint32_t pre_cache_min : 7;
		};
	};

	union {
		uint32_t dword9;
		struct {
			uint32_t pre_ci_hi : 4;
			uint32_t pre_owner : 1;
			uint32_t dw9_resvd0 : 27;
		};
	};

	union {
		uint32_t dword10;
		struct {
			uint32_t pre_wq_pfn_hi : 20;
			uint32_t pre_ci_lo : 12;
		};
	};

	union {
		uint32_t dword11;
		uint32_t pre_wq_pfn_lo;
	};

	union {
		uint32_t dword12;
		/* high 32it of PI DMA  address */
		uint32_t pi_addr_hi;
	};

	union {
		uint32_t dword13;
		/* low 32it of PI DMA  address */
		uint32_t pi_addr_lo;
	};

	union {
		uint32_t dword14;
		struct {
			uint32_t wq_blk_pfn_hi : 23;
			uint32_t dw14_resvd0 : 9;
		};
	};

	union {
		uint32_t dword15;
		uint32_t wq_blk_pfn_lo;
	};
};

struct sssnic_txq_ctx {
	union {
		uint32_t dword0;
		struct {
			uint32_t pi : 16;
			uint32_t ci : 16;
		};
	};

	union {
		uint32_t dword1;
		struct {
			uint32_t sp : 1;
			uint32_t drop : 1;
			uint32_t dw_resvd0 : 30;
		};
	};

	union {
		uint32_t dword2;
		struct {
			uint32_t wq_pfn_hi : 20;
			uint32_t dw2_resvd0 : 3;
			uint32_t wq_owner : 1;
			uint32_t dw2_resvd1 : 8;
		};
	};

	union {
		uint32_t dword3;
		uint32_t wq_pfn_lo;
	};

	uint32_t dword4;

	union {
		uint32_t dword5;
		struct {
			uint32_t drop_on_thd : 16;
			uint32_t drop_off_thd : 16;
		};
	};
	union {
		uint32_t dword6;
		struct {
			uint32_t qid : 13;
			uint32_t dw6_resvd0 : 19;
		};
	};

	union {
		uint32_t dword7;
		struct {
			uint32_t vlan_tag : 16;
			uint32_t vlan_type : 3;
			uint32_t insert_mode : 2;
			uint32_t dw7_resvd0 : 2;
			uint32_t ceq_en : 1;
			uint32_t dw7_resvd1 : 8;
		};
	};

	union {
		uint32_t dword8;
		struct {
			uint32_t pre_cache_thd : 14;
			uint32_t pre_cache_max : 11;
			uint32_t pre_cache_min : 7;
		};
	};

	union {
		uint32_t dword9;
		struct {
			uint32_t pre_ci_hi : 4;
			uint32_t pre_owner : 1;
			uint32_t dw9_resvd0 : 27;
		};
	};

	union {
		uint32_t dword10;
		struct {
			uint32_t pre_wq_pfn_hi : 20;
			uint32_t pre_ci_lo : 12;
		};
	};

	union {
		uint32_t dword11;
		uint32_t pre_wq_pfn_lo;
	};

	uint32_t dword12;
	uint32_t dword13;

	union {
		uint32_t dword14;
		struct {
			uint32_t wq_blk_pfn_hi : 23;
			uint32_t dw14_resvd0 : 9;
		};
	};

	union {
		uint32_t dword15;
		uint32_t wq_blk_pfn_lo;
	};
};

enum sssnic_rxtxq_ctx_type {
	SSSNIC_TXQ_CTX,
	SSSNIC_RXQ_CTX,
};

struct sssnic_rxtxq_ctx {
	union {
		struct sssnic_rxq_ctx rxq;
		struct sssnic_txq_ctx txq;
	};
};

#define SSSNIC_RXTXQ_CTX_SIZE (sizeof(struct sssnic_rxtxq_ctx))

int sssnic_msix_attr_get(struct sssnic_hw *hw, uint16_t msix_idx,
	struct sssnic_msix_attr *attr);
int sssnic_msix_attr_set(struct sssnic_hw *hw, uint16_t msix_idx,
	struct sssnic_msix_attr *attr);
int sssnic_capability_get(struct sssnic_hw *hw, struct sssnic_capability *capa);
int sssnic_mac_addr_get(struct sssnic_hw *hw, uint8_t *addr);
int sssnic_mac_addr_update(struct sssnic_hw *hw, uint8_t *new, uint8_t *old);
int sssnic_mac_addr_add(struct sssnic_hw *hw, uint8_t *addr);
int sssnic_mac_addr_del(struct sssnic_hw *hw, uint8_t *addr);
int sssnic_netif_link_status_get(struct sssnic_hw *hw, uint8_t *status);
int sssnic_netif_link_info_get(struct sssnic_hw *hw,
	struct sssnic_netif_link_info *info);
int sssnic_netif_enable_set(struct sssnic_hw *hw, uint8_t state);
int sssnic_port_enable_set(struct sssnic_hw *hw, bool state);
int sssnic_rxq_flush(struct sssnic_hw *hw, uint16_t qid);
int sssnic_rxtx_max_size_init(struct sssnic_hw *hw, uint16_t rx_size,
	uint16_t tx_size);
int sssnic_tx_max_size_set(struct sssnic_hw *hw, uint16_t tx_size);
int sssnic_port_features_get(struct sssnic_hw *hw, uint64_t *features);
int sssnic_port_features_set(struct sssnic_hw *hw, uint64_t features);
int sssnic_txq_ctx_set(struct sssnic_hw *hw, struct sssnic_txq_ctx *ctx,
	uint16_t qstart, uint16_t count);
int sssnic_rxq_ctx_set(struct sssnic_hw *hw, struct sssnic_rxq_ctx *ctx,
	uint16_t qstart, uint16_t count);
int sssnic_rx_offload_ctx_reset(struct sssnic_hw *hw);
int sssnic_tx_offload_ctx_reset(struct sssnic_hw *hw);
int sssnic_rxtx_ctx_set(struct sssnic_hw *hw, bool lro_en, uint16_t rxq_depth,
	uint16_t rx_buf, uint16_t txq_depth);
int sssnic_port_tx_ci_attr_set(struct sssnic_hw *hw, uint16_t tx_qid,
	uint8_t pending_limit, uint8_t coalescing_time, uint64_t dma_addr);
int sssnic_port_rx_mode_set(struct sssnic_hw *hw, uint32_t mode);
int sssnic_lro_enable_set(struct sssnic_hw *hw, bool ipv4_en, bool ipv6_en,
	uint8_t nb_lro_bufs);
int sssnic_lro_timer_set(struct sssnic_hw *hw, uint32_t timer);
int sssnic_vlan_filter_enable_set(struct sssnic_hw *hw, bool state);
int sssnic_vlan_strip_enable_set(struct sssnic_hw *hw, bool state);
int sssnic_port_resource_clean(struct sssnic_hw *hw);

#endif /* _SSSNIC_API_H_ */
