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

struct sssnic_port_stats {
	uint64_t tx_ucast_pkts;
	uint64_t tx_ucast_bytes;
	uint64_t tx_mcast_pkts;
	uint64_t tx_mcast_bytes;
	uint64_t tx_bcast_pkts;
	uint64_t tx_bcast_bytes;

	uint64_t rx_ucast_pkts;
	uint64_t rx_ucast_bytes;
	uint64_t rx_mcast_pkts;
	uint64_t rx_mcast_bytes;
	uint64_t rx_bcast_pkts;
	uint64_t rx_bcast_bytes;

	uint64_t tx_discards;
	uint64_t rx_discards;
	uint64_t tx_errors;
	uint64_t rx_errors;
};

struct sssnic_mac_stats {
	uint64_t tx_fragment_pkts;
	uint64_t tx_undersize_pkts;
	uint64_t tx_undermin_pkts;
	uint64_t tx_64b_pkts;
	uint64_t tx_65b_127b_pkt;
	uint64_t tx_128b_255b_pkts;
	uint64_t tx_256b_511b_pkts;
	uint64_t tx_512b_1023b_pkts;
	uint64_t tx_1024b_1518b_pkts;
	uint64_t tx_1519b_2047b_pkts;
	uint64_t tx_2048b_4095b_pkts;
	uint64_t tx_4096b_8191b_pkts;
	uint64_t tx_8192b_9216b_pkts;
	uint64_t tx_9217b_12287b_pkts;
	uint64_t tx_12288b_16383b_pkts;
	uint64_t tx_1519b_bad_pkts;
	uint64_t tx_1519b_good_pkts;
	uint64_t tx_oversize_pkts;
	uint64_t tx_jabber_pkts;
	uint64_t tx_bad_pkts;
	uint64_t tx_bad_bytes;
	uint64_t tx_good_pkts;
	uint64_t tx_good_bytes;
	uint64_t tx_total_pkts;
	uint64_t tx_total_bytes;
	uint64_t tx_unicast_pkts;
	uint64_t tx_multicast_bytes;
	uint64_t tx_broadcast_pkts;
	uint64_t tx_pause_pkts;
	uint64_t tx_pfc_pkts;
	uint64_t tx_pfc_pri0_pkts;
	uint64_t tx_pfc_pri1_pkts;
	uint64_t tx_pfc_pri2_pkts;
	uint64_t tx_pfc_pri3_pkts;
	uint64_t tx_pfc_pri4_pkts;
	uint64_t tx_pfc_pri5_pkts;
	uint64_t tx_pfc_pri6_pkts;
	uint64_t tx_pfc_pri7_pkts;
	uint64_t tx_control_pkts;
	uint64_t tx_total_error_pkts;
	uint64_t tx_debug_good_pkts;
	uint64_t tx_debug_bad_pkts;

	uint64_t rx_fragment_pkts;
	uint64_t rx_undersize_pkts;
	uint64_t rx_undermin_pkts;
	uint64_t rx_64b_pkts;
	uint64_t rx_65b_127b_pkt;
	uint64_t rx_128b_255b_pkts;
	uint64_t rx_256b_511b_pkts;
	uint64_t rx_512b_1023b_pkts;
	uint64_t rx_1024b_1518b_pkts;
	uint64_t rx_1519b_2047b_pkts;
	uint64_t rx_2048b_4095b_pkts;
	uint64_t rx_4096b_8191b_pkts;
	uint64_t rx_8192b_9216b_pkts;
	uint64_t rx_9217b_12287b_pkts;
	uint64_t rx_12288b_16383b_pkts;
	uint64_t rx_1519b_bad_pkts;
	uint64_t rx_1519b_good_pkts;
	uint64_t rx_oversize_pkts;
	uint64_t rx_jabber_pkts;
	uint64_t rx_bad_pkts;
	uint64_t rx_bad_bytes;
	uint64_t rx_good_pkts;
	uint64_t rx_good_bytes;
	uint64_t rx_total_pkts;
	uint64_t rx_total_bytes;
	uint64_t rx_unicast_pkts;
	uint64_t rx_multicast_bytes;
	uint64_t rx_broadcast_pkts;
	uint64_t rx_pause_pkts;
	uint64_t rx_pfc_pkts;
	uint64_t rx_pfc_pri0_pkts;
	uint64_t rx_pfc_pri1_pkts;
	uint64_t rx_pfc_pri2_pkts;
	uint64_t rx_pfc_pri3_pkts;
	uint64_t rx_pfc_pri4_pkts;
	uint64_t rx_pfc_pri5_pkts;
	uint64_t rx_pfc_pri6_pkts;
	uint64_t rx_pfc_pri7_pkts;
	uint64_t rx_control_pkts;
	uint64_t rx_symbol_error_pkts;
	uint64_t rx_fcs_error_pkts;
	uint64_t rx_debug_good_pkts;
	uint64_t rx_debug_bad_pkts;
	uint64_t rx_unfilter_pkts;
};

struct sssnic_rss_type {
	union {
		uint32_t mask;
		struct {
			uint32_t resvd : 23;
			uint32_t valid : 1;
			uint32_t ipv6_tcp_ex : 1;
			uint32_t ipv6_ex : 1;
			uint32_t ipv6_tcp : 1;
			uint32_t ipv6 : 1;
			uint32_t ipv4_tcp : 1;
			uint32_t ipv4 : 1;
			uint32_t ipv6_udp : 1;
			uint32_t ipv4_udp : 1;
		};
	};
};

enum sssnic_rss_hash_engine_type {
	SSSNIC_RSS_HASH_ENGINE_XOR,
	SSSNIC_RSS_HASH_ENGINE_TOEP,
	SSSNIC_RSS_HASH_ENGINE_COUNT,
};

#define SSSNIC_FW_VERSION_LEN 16
#define SSSNIC_FW_TIME_LEN 20
struct sssnic_fw_version {
	char version[SSSNIC_FW_VERSION_LEN];
	char time[SSSNIC_FW_VERSION_LEN];
};

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
int sssnic_port_stats_get(struct sssnic_hw *hw,
	struct sssnic_port_stats *stats);
int sssnic_port_stats_clear(struct sssnic_hw *hw);
int sssnic_mac_stats_get(struct sssnic_hw *hw, struct sssnic_mac_stats *stats);
int sssnic_mac_stats_clear(struct sssnic_hw *hw);
int sssnic_rss_enable_set(struct sssnic_hw *hw, bool state);
int sssnic_rss_profile_create(struct sssnic_hw *hw);
int sssnic_rss_profile_destroy(struct sssnic_hw *hw);
int sssnic_rss_hash_key_set(struct sssnic_hw *hw, uint8_t *key, uint16_t len);
int sssnic_rss_type_set(struct sssnic_hw *hw, struct sssnic_rss_type *type);
int sssnic_rss_type_get(struct sssnic_hw *hw, struct sssnic_rss_type *type);
int sssnic_rss_hash_engine_set(struct sssnic_hw *hw,
	enum sssnic_rss_hash_engine_type engine);
int sssnic_rss_indir_table_set(struct sssnic_hw *hw, const uint16_t *entry,
	uint32_t num_entries);
int sssnic_rss_indir_table_get(struct sssnic_hw *hw, uint16_t *entry,
	uint32_t num_entries);
int sssnic_fw_version_get(struct sssnic_hw *hw,
	struct sssnic_fw_version *version);
int sssnic_flow_ctrl_set(struct sssnic_hw *hw, bool autoneg, bool rx_en,
	bool tx_en);
int sssnic_flow_ctrl_get(struct sssnic_hw *hw, bool *autoneg, bool *rx_en,
	bool *tx_en);
int sssnic_vlan_filter_set(struct sssnic_hw *hw, uint16_t vid, bool add);

#endif /* _SSSNIC_API_H_ */
