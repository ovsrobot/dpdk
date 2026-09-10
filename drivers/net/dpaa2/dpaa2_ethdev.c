/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 * Copyright 2016-2026 NXP
 */

#include <time.h>
#include <net/if.h>
#include <unistd.h>
#include <errno.h>

#include <eal_export.h>
#include <rte_mbuf.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <dev_driver.h>
#include <bus_fslmc_driver.h>
#include <rte_flow_driver.h>
#include "rte_dpaa2_mempool.h"

#include "dpaa2_pmd_logs.h"
#include <fslmc_vfio.h>
#include <dpaa2_hw_pvt.h>
#include <dpaa2_hw_mempool.h>
#include <dpaa2_hw_dpio.h>
#include <fsl_dprc.h>
#include <mc/fsl_dpmng.h>
#include <mc/fsl_dpcon.h>
#include "dpaa2_ethdev.h"
#include <fsl_qbman_debug.h>

#define DRIVER_LOOPBACK_MODE "drv_loopback"
#define DRIVER_NO_PREFETCH_MODE "drv_no_prefetch"
#define DRIVER_TX_CONF "drv_tx_conf"
#define DRIVER_TX_DYNAMIC_CONF "drv_tx_dyn_conf"
#define DRIVER_TX_DYNAMIC_CONF_PREFETCH "drv_tx_dyn_conf_pre"
#define DRIVER_RX_PARSE_ERR_DROP "drv_rx_parse_drop"
#define DRIVER_ERROR_QUEUE  "drv_err_queue"
#define DRIVER_NO_TAILDROP  "drv_no_taildrop"
#define DRIVER_NO_DATA_STASHING "drv_no_data_stashing"
#define CHECK_INTERVAL         100  /* 100ms */
#define MAX_REPEAT_TIME        90   /* 9s (90 * 100ms) in total */

/* Supported Rx offloads */
static uint64_t dev_rx_offloads_sup =
		RTE_ETH_RX_OFFLOAD_CHECKSUM |
		RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
		RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
		RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM |
		RTE_ETH_RX_OFFLOAD_VLAN_FILTER |
		RTE_ETH_RX_OFFLOAD_TIMESTAMP;

/* Rx offloads which cannot be disabled */
static uint64_t dev_rx_offloads_nodis =
		RTE_ETH_RX_OFFLOAD_RSS_HASH |
		RTE_ETH_RX_OFFLOAD_SCATTER;

/* Supported Tx offloads */
static uint64_t dev_tx_offloads_sup =
		RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM |
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM |
		RTE_ETH_TX_OFFLOAD_MT_LOCKFREE |
		RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

/* Tx offloads which cannot be disabled */
static uint64_t dev_tx_offloads_nodis =
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

/* Rx descriptor limit when DPNI loads PFDRs in PEB */
#define MAX_NB_RX_DESC_IN_PEB	11264
static int total_nb_rx_desc;

/* Size of the RETA (Redirection Table) we expose to the standard DPDK API.
 * Must be a multiple of RTE_ETH_RETA_GROUP_SIZE (64). DPAA2 has no actual
 * indirection table in HW; this is the granularity at which uniform RSS
 * patterns are inspected by dpaa2_dev_rss_reta_update().
 */
#define DPAA2_RETA_SIZE		64
int dpaa2_valid_dev;
struct rte_mempool *dpaa2_tx_sg_pool;

struct dpaa2_xstats_seq {
	struct dpni_statistics_page_0 pg0;
	struct dpni_statistics_page_1 pg1;
	struct dpni_statistics_page_2 pg2;
	struct dpni_statistics_page_3 pg3;
	struct dpni_statistics_page_4 pg4;
	struct dpni_statistics_page_5 pg5[MAX_TCS];
	struct dpni_statistics_page_6 pg6;
	struct dpni_dpmac_counters mac_cnt;
};

#define DPAA2_XSTAT_MAX_NUM \
	(sizeof(struct dpaa2_xstats_seq) / sizeof(uint64_t))

#define DPAA2_DPNI_XSTAT_MAX_NUM \
	(offsetof(struct dpaa2_xstats_seq, mac_cnt) / sizeof(uint64_t))

#define DPAA2_MAC_XSTAT_MAX_NUM DPAA2_MAC_NUM_STATS

static_assert((DPAA2_DPNI_XSTAT_MAX_NUM + DPAA2_MAC_XSTAT_MAX_NUM) ==
	DPAA2_XSTAT_MAX_NUM, "DPNI and MAC xstats do not sum to total");

#define DPAA2_DPNI_STAT_SET_PAGE_PARAM(param) \
({ \
	int ret = false; \
	\
	if ((id) >= this_offset && (id) < (this_offset + pg_size)) { \
		_stat_id = (id) - this_offset; \
		_param = param; \
		_size = pg_size; \
		ret = true; \
	} \
	ret; \
})

#define DPAA2_DPNI_STAT_PAGE_PARAM(pid) \
({ \
	uint64_t this_offset = offsetof(struct dpaa2_xstats_seq, pg##pid) / sizeof(uint64_t); \
	uint64_t pg_size = sizeof(struct dpni_statistics_page_##pid) / sizeof(uint64_t); \
	int ret; \
	\
	ret = DPAA2_DPNI_STAT_SET_PAGE_PARAM(0); \
	if (!ret) \
		_page++; \
	ret; \
})

#define DPAA2_DPNI_STAT_POLICER_PAGE_PARAM() \
({ \
	int ret = false; \
	uint8_t tc_id; \
	uint64_t this_offset; \
	uint64_t pg_size = sizeof(struct dpni_statistics_page_5) / sizeof(uint64_t); \
	\
	for (tc_id = 0; tc_id < MAX_TCS; tc_id++) { \
		this_offset = offsetof(struct dpaa2_xstats_seq, pg5[tc_id]) / sizeof(uint64_t); \
		ret = DPAA2_DPNI_STAT_SET_PAGE_PARAM(tc_id); \
		if (ret) \
			break; \
	} \
	if (!ret) \
		_page++; \
	ret; \
})

static inline int
dpaa2_xstats_id_parse(uint32_t id, uint8_t *page,
	uint8_t *stat_id, uint16_t *param, uint16_t *size)
{
	uint8_t _page = DPNI_INGRESS_STATISTICS_PAGE_ID, _stat_id = 0;
	uint16_t _param = 0, _size = 0;

	if (DPAA2_DPNI_STAT_PAGE_PARAM(0))
		goto found_id;
	if (DPAA2_DPNI_STAT_PAGE_PARAM(1))
		goto found_id;
	if (DPAA2_DPNI_STAT_PAGE_PARAM(2))
		goto found_id;
	if (DPAA2_DPNI_STAT_PAGE_PARAM(3))
		goto found_id;
	if (DPAA2_DPNI_STAT_PAGE_PARAM(4))
		goto found_id;
	if (DPAA2_DPNI_STAT_POLICER_PAGE_PARAM())
		goto found_id;
	if (DPAA2_DPNI_STAT_PAGE_PARAM(6))
		goto found_id;

	DPAA2_PMD_ERR("ID(%d) was not found in DPNI page statistics", id);
	return -EINVAL;

found_id:
	if (page)
		*page = _page;
	if (stat_id)
		*stat_id = _stat_id;
	if (param)
		*param = _param;
	if (size)
		*size = _size;

	return 0;
}

#define DPAA2_XSTAT_ID(field) \
	(offsetof(struct dpaa2_xstats_seq, field) / sizeof(uint64_t))

#define DPAA2_XSTAT_STR_SET(pg, field) \
	[DPAA2_XSTAT_ID(pg.field)] = RTE_STR(field)

#define DPAA2_XSTAT_TC_STR_SET(pg, tc, field) \
	[DPAA2_XSTAT_ID(pg[tc].field)] = "TC" RTE_STR(tc)"_" RTE_STR(field)

#define DPAA2_XSTAT_TC_COLOR_STR_SET(pg, tc) \
	DPAA2_XSTAT_TC_STR_SET(pg, tc, policer_cnt_red), \
	DPAA2_XSTAT_TC_STR_SET(pg, tc, policer_cnt_yellow), \
	DPAA2_XSTAT_TC_STR_SET(pg, tc, policer_cnt_green), \
	DPAA2_XSTAT_TC_STR_SET(pg, tc, policer_cnt_re_red), \
	DPAA2_XSTAT_TC_STR_SET(pg, tc, policer_cnt_re_yellow)

#define DPAA2_MAC_XSTAT_STR_SET(name) \
	[DPAA2_XSTAT_ID(mac_cnt.name)] = "mac_" RTE_STR(name)

#define DPAA2_MAC_XSTAT_PFC_STR_SET(dir, tc) \
	[DPAA2_XSTAT_ID(mac_cnt.dir##_pfc_class[tc])] = \
		"mac_" RTE_STR(dir) "_pfc_class_" RTE_STR(tc)

static const char * const
dpaa2_xstats_strings[DPAA2_XSTAT_MAX_NUM] = {
	DPAA2_XSTAT_STR_SET(pg0, ingress_all_frames),
	DPAA2_XSTAT_STR_SET(pg0, ingress_all_bytes),
	DPAA2_XSTAT_STR_SET(pg0, ingress_multicast_frames),
	DPAA2_XSTAT_STR_SET(pg0, ingress_multicast_bytes),
	DPAA2_XSTAT_STR_SET(pg0, ingress_broadcast_frames),
	DPAA2_XSTAT_STR_SET(pg0, ingress_broadcast_bytes),

	DPAA2_XSTAT_STR_SET(pg1, egress_all_frames),
	DPAA2_XSTAT_STR_SET(pg1, egress_all_bytes),
	DPAA2_XSTAT_STR_SET(pg1, egress_multicast_frames),
	DPAA2_XSTAT_STR_SET(pg1, egress_multicast_bytes),
	DPAA2_XSTAT_STR_SET(pg1, egress_broadcast_frames),
	DPAA2_XSTAT_STR_SET(pg1, egress_broadcast_bytes),

	DPAA2_XSTAT_STR_SET(pg2, ingress_filtered_frames),
	DPAA2_XSTAT_STR_SET(pg2, ingress_discarded_frames),
	DPAA2_XSTAT_STR_SET(pg2, ingress_nobuffer_discards),
	DPAA2_XSTAT_STR_SET(pg2, egress_discarded_frames),
	DPAA2_XSTAT_STR_SET(pg2, egress_confirmed_frames),

	DPAA2_XSTAT_STR_SET(pg3, ceetm_dequeue_bytes),
	DPAA2_XSTAT_STR_SET(pg3, ceetm_dequeue_frames),
	DPAA2_XSTAT_STR_SET(pg3, ceetm_reject_bytes),
	DPAA2_XSTAT_STR_SET(pg3, ceetm_reject_frames),

	DPAA2_XSTAT_STR_SET(pg4, cgr_reject_frames),
	DPAA2_XSTAT_STR_SET(pg4, cgr_reject_bytes),

	DPAA2_XSTAT_TC_COLOR_STR_SET(pg5, 0),
	DPAA2_XSTAT_TC_COLOR_STR_SET(pg5, 1),
	DPAA2_XSTAT_TC_COLOR_STR_SET(pg5, 2),
	DPAA2_XSTAT_TC_COLOR_STR_SET(pg5, 3),
	DPAA2_XSTAT_TC_COLOR_STR_SET(pg5, 4),
	DPAA2_XSTAT_TC_COLOR_STR_SET(pg5, 5),
	DPAA2_XSTAT_TC_COLOR_STR_SET(pg5, 6),
	DPAA2_XSTAT_TC_COLOR_STR_SET(pg5, 7),

	DPAA2_XSTAT_STR_SET(pg6, tx_pending_frames_cnt),

	DPAA2_MAC_XSTAT_STR_SET(rx_64_bytes),
	DPAA2_MAC_XSTAT_STR_SET(rx_65_127_bytes),
	DPAA2_MAC_XSTAT_STR_SET(rx_128_255_bytes),
	DPAA2_MAC_XSTAT_STR_SET(rx_256_511_bytes),
	DPAA2_MAC_XSTAT_STR_SET(rx_512_1023_bytes),
	DPAA2_MAC_XSTAT_STR_SET(rx_1024_1518_bytes),
	DPAA2_MAC_XSTAT_STR_SET(rx_1519_max_bytes),

	DPAA2_MAC_XSTAT_STR_SET(rx_fragments),
	DPAA2_MAC_XSTAT_STR_SET(rx_jabber),
	DPAA2_MAC_XSTAT_STR_SET(rx_drop_fifo),
	DPAA2_MAC_XSTAT_STR_SET(rx_alignment_error),

	DPAA2_MAC_XSTAT_STR_SET(tx_undersize_good),
	DPAA2_MAC_XSTAT_STR_SET(rx_oversize_good),

	DPAA2_MAC_XSTAT_STR_SET(rx_pause),
	DPAA2_MAC_XSTAT_STR_SET(tx_pause),

	DPAA2_MAC_XSTAT_STR_SET(rx_good_bytes),
	DPAA2_MAC_XSTAT_STR_SET(rx_multicast),
	DPAA2_MAC_XSTAT_STR_SET(rx_broadcast),
	DPAA2_MAC_XSTAT_STR_SET(rx_all_frames),
	DPAA2_MAC_XSTAT_STR_SET(rx_unicast),
	DPAA2_MAC_XSTAT_STR_SET(rx_error),

	DPAA2_MAC_XSTAT_STR_SET(tx_good_bytes),
	DPAA2_MAC_XSTAT_STR_SET(tx_multicast),
	DPAA2_MAC_XSTAT_STR_SET(tx_broadcast),
	DPAA2_MAC_XSTAT_STR_SET(tx_unicast),
	DPAA2_MAC_XSTAT_STR_SET(tx_error),

	DPAA2_MAC_XSTAT_STR_SET(rx_valid_frames),
	DPAA2_MAC_XSTAT_STR_SET(tx_valid_frames),

	DPAA2_MAC_XSTAT_STR_SET(tx_64_bytes),
	DPAA2_MAC_XSTAT_STR_SET(tx_65_127_bytes),
	DPAA2_MAC_XSTAT_STR_SET(tx_128_255_bytes),
	DPAA2_MAC_XSTAT_STR_SET(tx_256_511_bytes),
	DPAA2_MAC_XSTAT_STR_SET(tx_512_1023_bytes),
	DPAA2_MAC_XSTAT_STR_SET(tx_1024_1518_bytes),
	DPAA2_MAC_XSTAT_STR_SET(tx_1519_max_bytes),

	DPAA2_MAC_XSTAT_STR_SET(rx_bytes_all),
	DPAA2_MAC_XSTAT_STR_SET(rx_crc_error),
	DPAA2_MAC_XSTAT_STR_SET(rx_vlan),
	DPAA2_MAC_XSTAT_STR_SET(rx_undersize_good),
	DPAA2_MAC_XSTAT_STR_SET(rx_ctrl_non_pause),
	DPAA2_MAC_XSTAT_STR_SET(rx_drop_full),

	DPAA2_MAC_XSTAT_STR_SET(tx_bytes_all),
	DPAA2_MAC_XSTAT_STR_SET(tx_crc_error),
	DPAA2_MAC_XSTAT_STR_SET(tx_vlan),
	DPAA2_MAC_XSTAT_STR_SET(tx_all_frames),
	DPAA2_MAC_XSTAT_STR_SET(tx_ctrl_non_pause),

	DPAA2_MAC_XSTAT_PFC_STR_SET(rx, 0),
	DPAA2_MAC_XSTAT_PFC_STR_SET(rx, 1),
	DPAA2_MAC_XSTAT_PFC_STR_SET(rx, 2),
	DPAA2_MAC_XSTAT_PFC_STR_SET(rx, 3),
	DPAA2_MAC_XSTAT_PFC_STR_SET(rx, 4),
	DPAA2_MAC_XSTAT_PFC_STR_SET(rx, 5),
	DPAA2_MAC_XSTAT_PFC_STR_SET(rx, 6),
	DPAA2_MAC_XSTAT_PFC_STR_SET(rx, 7),

	DPAA2_MAC_XSTAT_PFC_STR_SET(tx, 0),
	DPAA2_MAC_XSTAT_PFC_STR_SET(tx, 1),
	DPAA2_MAC_XSTAT_PFC_STR_SET(tx, 2),
	DPAA2_MAC_XSTAT_PFC_STR_SET(tx, 3),
	DPAA2_MAC_XSTAT_PFC_STR_SET(tx, 4),
	DPAA2_MAC_XSTAT_PFC_STR_SET(tx, 5),
	DPAA2_MAC_XSTAT_PFC_STR_SET(tx, 6),
	DPAA2_MAC_XSTAT_PFC_STR_SET(tx, 7)
};

#define DPAA2_DPNI_XSTAT_FIELD_ID(field) \
	(offsetof(struct dpaa2_xstats_seq, field) / sizeof(uint64_t))

static const struct rte_eth_stats dpaa2_stats_xstat_ids = {
	.ipackets = DPAA2_DPNI_XSTAT_FIELD_ID(pg0.ingress_all_frames),
	.opackets = DPAA2_DPNI_XSTAT_FIELD_ID(pg1.egress_all_frames),
	.ibytes = DPAA2_DPNI_XSTAT_FIELD_ID(pg0.ingress_all_bytes),
	.obytes = DPAA2_DPNI_XSTAT_FIELD_ID(pg1.egress_all_bytes),
	.imissed = DPAA2_DPNI_XSTAT_FIELD_ID(pg2.ingress_filtered_frames),
	.ierrors = DPAA2_DPNI_XSTAT_FIELD_ID(pg2.ingress_discarded_frames),
	.oerrors = DPAA2_DPNI_XSTAT_FIELD_ID(pg2.egress_discarded_frames),
	.rx_nombuf = DPAA2_DPNI_XSTAT_FIELD_ID(pg2.ingress_nobuffer_discards)
};

#define DPAA2_STATS_XSTATS_NUM \
	(sizeof(dpaa2_stats_xstat_ids) / sizeof(uint64_t))

#define DPAA2_MAC_XSTATS_START_ID DPAA2_DPNI_XSTAT_MAX_NUM


static struct rte_dpaa2_driver rte_dpaa2_pmd;
static int dpaa2_dev_link_update(struct rte_eth_dev *dev,
				 int wait_to_complete);
static int dpaa2_dev_set_link_up(struct rte_eth_dev *dev);
static int dpaa2_dev_set_link_down(struct rte_eth_dev *dev);
static int dpaa2_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
static int
dpaa2_setup_table_miss_action(struct rte_eth_dev *eth_dev,
	uint8_t tc_index)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct rte_flow_group_attr attr;
	struct rte_flow_action actions[2];
	struct dpaa2_flow_tbl_profile *tbl_profile;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;
	if (tc_index < priv->num_rx_tc) {
		tbl_profile = &priv->flow_profile.tc_profile[tc_index];
		if (tbl_profile->default_drop) {
			actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		} else if (tbl_profile->default_queue.index >= eth_dev->data->nb_rx_queues) {
			DPAA2_PMD_DEBUG("%s-tc%d-default-rxq(%d) >= max rxq(%d), Force to drop.",
				eth_dev->data->name, tc_index, tbl_profile->default_queue.index,
				eth_dev->data->nb_rx_queues);
			tbl_profile->default_drop = true;
			actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		} else {
			actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
			actions[0].conf = &tbl_profile->default_queue;
		}
	} else {
		tbl_profile = &priv->flow_profile.qos_profile;
		if (tbl_profile->default_drop) {
			actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		} else if (tbl_profile->default_jump.group >= priv->num_rx_tc) {
			DPAA2_PMD_DEBUG("%s-default-tc(%d) >= max tc(%d), Force to drop.",
				eth_dev->data->name, tbl_profile->default_jump.group,
				priv->num_rx_tc);
			tbl_profile->default_drop = true;
			actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
		} else {
			actions[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
			actions[0].conf = &tbl_profile->default_jump;
		}
	}
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	return rte_flow_group_set_miss_actions(eth_dev->data->port_id,
			tc_index, &attr, actions, NULL);
}

static int
dpaa2_setup_flow_rss_dist(struct rte_eth_dev *eth_dev,
	uint64_t req_dist_set, int tc_index)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	int tc_dist_queues;
	struct rte_flow_attr attr;
	struct rte_flow_action_rss action_rss;
	struct rte_flow_action actions[2];
	struct rte_flow *rss_flow;

	/*TC distribution size is set with dist_queues or
	 * nb_rx_queues % dist_queues in order of TC priority index.
	 * Calculating dist size for this tc_index:-
	 */
	tc_dist_queues = eth_dev->data->nb_rx_queues -
		tc_index * priv->dist_queues;
	if (tc_dist_queues <= 0) {
		DPAA2_PMD_DEBUG("No distribution on TC%d", tc_index);
		return 0;
	}

	if (tc_dist_queues > priv->dist_queues)
		tc_dist_queues = priv->dist_queues;

	memset(&attr, 0, sizeof(attr));
	action_rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	action_rss.level = 0;
	action_rss.types = req_dist_set;
	action_rss.key_len = 0;
	action_rss.key = NULL;
	action_rss.queue = NULL;
	action_rss.queue_num = tc_dist_queues;

	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = &action_rss;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	attr.group = tc_index;
	attr.ingress = 1;
	rss_flow = rte_flow_create(eth_dev->data->port_id, &attr, NULL, actions, NULL);
	if (!rss_flow) {
		DPAA2_PMD_WARN("%s: Set RSS flow dist on tc%d failed",
			__func__, tc_index);
		return -EIO;
	}

	return 0;
}

static int
dpaa2_setup_flow_dcb_dist(struct rte_eth_dev *eth_dev,
	uint8_t prio, uint8_t tc)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct rte_flow_attr attr;
	struct rte_flow_action actions[2];
	struct rte_flow_item_vlan vlan_item;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item items[2];
	struct rte_flow_action_jump action_jump;
	struct rte_flow *qos_flow;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	attr.group = priv->num_rx_tc;
	attr.priority = prio;
	memset(&vlan_item, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
	vlan_item.hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_TCI_MAKE(0, prio, 0));
	vlan_mask.hdr.vlan_tci = rte_cpu_to_be_16(RTE_VLAN_PRI_MASK);
	items[0].spec = &vlan_item;
	items[0].mask = &vlan_mask;
	items[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
	items[1].type = RTE_FLOW_ITEM_TYPE_END;

	actions[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
	action_jump.group = tc;
	actions[0].conf = &action_jump;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	qos_flow = rte_flow_create(eth_dev->data->port_id,
		&attr, items, actions, NULL);
	if (!qos_flow) {
		DPAA2_PMD_WARN("Failed to direct vlan with prio(%d) to tc%d", prio, tc);
		return -EIO;
	}
	priv->dcb_flow[prio] = qos_flow;

	return 0;
}

static int
dpaa2_remove_flow_rss_dist(struct rte_eth_dev *eth_dev,
	uint8_t tc_index)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct dpaa2_flow_tbl_profile *tbl_profile;
	int ret;

	tbl_profile = &priv->flow_profile.tc_profile[tc_index];
	if (!tbl_profile->rss_flow || !tbl_profile->is_rss) {
		DPAA2_PMD_WARN("%s'TC[%d] is not RSS distributed",
			eth_dev->data->name, tc_index);
		return 0;
	}
	ret = rte_flow_destroy(eth_dev->data->port_id, tbl_profile->rss_flow, NULL);
	if (ret)
		return ret;
	tbl_profile->rss_flow = NULL;

	return 0;
}

static int
dpaa2_update_flow_rss_dist(struct rte_eth_dev *eth_dev,
	uint64_t req_dist_set, int tc_index)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct dpaa2_flow_tbl_profile *tbl_profile;
	struct rte_flow_action_rss action_rss;
	struct rte_flow_action actions[2];
	int ret;

	tbl_profile = &priv->flow_profile.tc_profile[tc_index];
	if (!tbl_profile->rss_flow || !tbl_profile->is_rss) {
		DPAA2_PMD_WARN("%s'TC[%d] is not RSS distributed",
			eth_dev->data->name, tc_index);
		return 0;
	}
	action_rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	action_rss.level = 0;
	action_rss.types = req_dist_set;
	action_rss.key_len = 0;
	action_rss.queue_num = tbl_profile->tc_cfg.dist_size;
	action_rss.key = NULL;
	action_rss.queue = NULL;
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = &action_rss;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	ret = rte_flow_actions_update(eth_dev->data->port_id, tbl_profile->rss_flow,
		actions, NULL);

	return ret;
}

static int
dpaa2_attach_bp_list(struct dpaa2_dev_priv *priv,
	struct fsl_mc_io *dpni, void *blist, uint8_t tc_id)
{
	/* Function to attach a DPNI with a buffer pool list. Buffer pool list
	 * handle is passed in blist.
	 */
	int32_t retcode;
	struct dpni_pools_cfg *bpool_cfg = &priv->pools_cfg;
	struct dpaa2_bp_list *bp_list = blist;
	struct dpni_buffer_layout layout;
	int tot_size, out_min_hdr_room, in_min_hdr_room;
	uint8_t bp_idx;
	struct rte_mempool *mp = bp_list->mp;

	if (priv->flow_profile.mempool[tc_id] != mp) {
		if (!priv->flow_profile.mempool[tc_id]) {
			bp_idx = bpool_cfg->num_dpbp;
			bpool_cfg->num_dpbp++;
			priv->flow_profile.bp_idx[tc_id] = bp_idx;
		} else {
			bp_idx = priv->flow_profile.bp_idx[tc_id];
		}
		priv->flow_profile.mempool[tc_id] = mp;
	} else {
		bp_idx = priv->flow_profile.bp_idx[tc_id];
	}

	/* ... rx buffer layout .
	 * Check alignment for buffer layouts first
	 */

	/* ... rx buffer layout ... */
	if (priv->tx_conf_type == DPAA2_TX_DYNAMIC_CONF) {
		/** Additional headroom layout for IPSec with TX configure
		 * dynamic enabled.
		 */
		in_min_hdr_room = DPAA2_RX_MIN_FD_OFFSET +
			DPAA2_SEC_SIMPLE_FD_IB_MIN;
		out_min_hdr_room = DPAA2_DYN_TX_MIN_FD_OFFSET +
			DPAA2_SEC_SIMPLE_FD_OB_MIN;
		tot_size = RTE_MAX(in_min_hdr_room, out_min_hdr_room);
		if (tot_size < RTE_PKTMBUF_HEADROOM)
			tot_size = RTE_PKTMBUF_HEADROOM;
	} else {
		tot_size = RTE_PKTMBUF_HEADROOM;
	}
	tot_size = RTE_ALIGN_CEIL(tot_size, DPAA2_PACKET_LAYOUT_ALIGN);

	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_DATA_HEAD_ROOM |
		DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
		DPNI_BUF_LAYOUT_OPT_PARSER_RESULT |
		DPNI_BUF_LAYOUT_OPT_DATA_ALIGN |
		DPNI_BUF_LAYOUT_OPT_TIMESTAMP |
		DPNI_BUF_LAYOUT_OPT_PRIVATE_DATA_SIZE;

	layout.pass_timestamp = true;
	layout.pass_frame_status = 1;
	layout.private_data_size = DPAA2_FD_PTA_SIZE;
	layout.pass_parser_result = 1;
	layout.data_align = DPAA2_PACKET_LAYOUT_ALIGN;
	layout.data_head_room = tot_size - DPAA2_FD_PTA_SIZE -
		DPAA2_MBUF_HW_ANNOTATION;
	retcode = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, priv->token,
			DPNI_QUEUE_RX, &layout);
	if (retcode) {
		DPAA2_PMD_ERR("Error configuring buffer pool Rx layout (%d)",
			retcode);
		return retcode;
	}

	/*Attach buffer pool to the network interface as described by the user*/
	bpool_cfg->pools[bp_idx].dpbp_id = bp_list->buf_pool.dpbp_node->dpbp_id;
	bpool_cfg->pools[bp_idx].backup_pool = 0;
	bpool_cfg->pools[bp_idx].buffer_size = RTE_ALIGN_CEIL(bp_list->buf_pool.size,
		DPAA2_PACKET_LAYOUT_ALIGN);
	/* priority_mask is a bitmask of the traffic classes served by this
	 * buffer pool, not a traffic class index. MC treats a zero mask as
	 * 0xff (all traffic classes).
	 */
	bpool_cfg->pools[bp_idx].priority_mask = RTE_BIT32(tc_id);

	retcode = dpni_set_pools(dpni, CMD_PRI_LOW, priv->token, bpool_cfg);
	if (retcode) {
		DPAA2_PMD_ERR("Error(%d) configuring pools[%d](id=%d) on %s.",
			retcode, bp_idx, bpool_cfg->pools[bp_idx].dpbp_id,
			priv->eth_dev->data->name);
		return retcode;
	}

	priv->bp_list = bp_list;
	return 0;
}

static int
dpaa2_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;

	PMD_INIT_FUNC_TRACE();

	if (!dpni) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -EINVAL;
	}

	if (on)
		ret = dpni_add_vlan_id(dpni, CMD_PRI_LOW, priv->token,
				       vlan_id, 0, 0, 0);
	else
		ret = dpni_remove_vlan_id(dpni, CMD_PRI_LOW,
					  priv->token, vlan_id);

	if (ret < 0)
		DPAA2_PMD_ERR("ret = %d Unable to add/rem vlan %d hwid =%d",
			      ret, vlan_id, priv->hw_id);

	return ret;
}

static int
dpaa2_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	if (mask & RTE_ETH_VLAN_FILTER_MASK) {
		/* VLAN Filter not available */
		if (!priv->max_vlan_filters) {
			DPAA2_PMD_INFO("VLAN filter not available");
			return -ENOTSUP;
		}

		if (dev->data->dev_conf.rxmode.offloads &
			RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
			ret = dpni_enable_vlan_filter(dpni, CMD_PRI_LOW,
						      priv->token, true);
		else
			ret = dpni_enable_vlan_filter(dpni, CMD_PRI_LOW,
						      priv->token, false);
		if (ret < 0)
			DPAA2_PMD_INFO("Unable to set vlan filter = %d", ret);
	}

	return ret;
}

static int
dpaa2_vlan_tpid_set(struct rte_eth_dev *dev,
	enum rte_vlan_type vlan_type __rte_unused,
	uint16_t tpid)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	int ret = -ENOTSUP;

	PMD_INIT_FUNC_TRACE();

	/* nothing to be done for standard vlan tpids */
	if (tpid == 0x8100 || tpid == 0x88A8)
		return 0;

	ret = dpni_add_custom_tpid(dpni, CMD_PRI_LOW,
				   priv->token, tpid);
	if (ret < 0)
		DPAA2_PMD_INFO("Unable to set vlan tpid = %d", ret);
	/* if already configured tpids, remove them first */
	if (ret == -EBUSY) {
		struct dpni_custom_tpid_cfg tpid_list = {0};

		ret = dpni_get_custom_tpid(dpni, CMD_PRI_LOW,
				   priv->token, &tpid_list);
		if (ret < 0)
			goto fail;
		ret = dpni_remove_custom_tpid(dpni, CMD_PRI_LOW,
				   priv->token, tpid_list.tpid1);
		if (ret < 0)
			goto fail;
		ret = dpni_add_custom_tpid(dpni, CMD_PRI_LOW,
					   priv->token, tpid);
	}
fail:
	return ret;
}

static int
dpaa2_fw_version_get(struct rte_eth_dev *dev,
	char *fw_version, size_t fw_size)
{
	int ret;
	uint32_t major, minor, rev;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	struct mc_soc_version mc_plat_info = {0};

	PMD_INIT_FUNC_TRACE();

	major = RTE_FSL_MC_REV_MAJOR(priv->mc_rev);
	minor = RTE_FSL_MC_REV_MINOR(priv->mc_rev);
	rev = RTE_FSL_MC_REV_REVISION(priv->mc_rev);
	if (mc_get_soc_version(dpni, CMD_PRI_LOW, &mc_plat_info))
		DPAA2_PMD_WARN("\tmc_get_soc_version failed");

	ret = snprintf(fw_version, fw_size, "%x-%d.%d.%d",
		mc_plat_info.svr, major, minor, rev);
	if (ret < 0)
		return -EINVAL;

	ret += 1; /* add the size of '\0' */
	if (fw_size < (size_t)ret)
		return ret;
	else
		return 0;
}

static uint32_t dpaa2_speed_to_rte_link_speed(enum dpmac_link_speed dpmac_speed)
{
	switch (dpmac_speed) {
	case DPMAC_LINK_SPEED_10M:
		return RTE_ETH_LINK_SPEED_10M;
	case DPMAC_LINK_SPEED_100M:
		return RTE_ETH_LINK_SPEED_100M;
	case DPMAC_LINK_SPEED_1G:
		return RTE_ETH_LINK_SPEED_1G;
	case DPMAC_LINK_SPEED_2_5G:
		return RTE_ETH_LINK_SPEED_2_5G;
	case DPMAC_LINK_SPEED_5G:
		return RTE_ETH_LINK_SPEED_5G;
	case DPMAC_LINK_SPEED_10G:
		return RTE_ETH_LINK_SPEED_10G;
	case DPMAC_LINK_SPEED_25G:
		return RTE_ETH_LINK_SPEED_25G;
	case DPMAC_LINK_SPEED_40G:
		return RTE_ETH_LINK_SPEED_40G;
	case DPMAC_LINK_SPEED_50G:
		return RTE_ETH_LINK_SPEED_50G;
	case DPMAC_LINK_SPEED_100G:
		return RTE_ETH_LINK_SPEED_100G;
	default:
		return 0;
	}
}

static uint32_t dpaa2_dev_get_speed_capability(struct rte_eth_dev *dev)
{
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	enum dpmac_link_speed speed;
	uint32_t dpmac_speed_cap;
	uint32_t speed_capa = 0;
	int ret;

	/* The dpni_get_mac_supported_eth_if() API is only available starting
	 * with DPNI ver 8.6.
	 */
	if (dpaa2_dev_cmp_dpni_ver(priv, DPNI_GET_MAC_SUPPORTED_IFS_VER_MAJOR,
				   DPNI_GET_MAC_SUPPORTED_IFS_VER_MINOR) < 0)
		goto fallback;

	if (priv->ep_dev_type != DPAA2_MAC)
		goto fallback;

	ret = dpni_get_mac_speed_capability(dpni, CMD_PRI_LOW, priv->token,
					    &dpmac_speed_cap);
	if (ret < 0) {
		DPAA2_PMD_WARN("dpni_get_mac_speed_capability() failed with %d", ret);
		goto fallback;
	}
	for (speed = DPMAC_LINK_SPEED_10M; speed < DPMAC_LINK_SPEED_MAX; speed++) {
		if ((dpmac_speed_cap & (1 << speed)) == 0)
			continue;

		speed_capa |= dpaa2_speed_to_rte_link_speed(speed);
	}

	return speed_capa;

fallback:
	speed_capa = RTE_ETH_LINK_SPEED_1G | RTE_ETH_LINK_SPEED_2_5G |
		RTE_ETH_LINK_SPEED_10G;

	if (dpaa2_svr_family == SVR_LX2160A)
		speed_capa |= RTE_ETH_LINK_SPEED_25G | RTE_ETH_LINK_SPEED_40G |
			RTE_ETH_LINK_SPEED_50G | RTE_ETH_LINK_SPEED_100G;

	return speed_capa;
}

static int
dpaa2_dev_info_get(struct rte_eth_dev *dev,
	struct rte_eth_dev_info *dev_info)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	dev_info->max_mac_addrs = priv->max_mac_filters;
	dev_info->max_rx_pktlen = DPAA2_MAX_RX_PKT_LEN;
	dev_info->min_rx_bufsize = DPAA2_MIN_RX_BUF_SIZE;
	dev_info->max_rx_queues = (uint16_t)priv->nb_rx_queues;
	dev_info->max_tx_queues = (uint16_t)priv->nb_tx_queues;
	dev_info->rx_offload_capa = dev_rx_offloads_sup |
					dev_rx_offloads_nodis;
	dev_info->tx_offload_capa = dev_tx_offloads_sup |
					dev_tx_offloads_nodis;
	dev_info->dev_capa = 0;

	dev_info->max_hash_mac_addrs = 0;
	dev_info->max_vfs = 0;
	dev_info->max_vmdq_pools = RTE_ETH_16_POOLS;
	dev_info->flow_type_rss_offloads = DPAA2_RSS_OFFLOAD_ALL;
	/* DPAA2 has no software-visible indirection table: incoming packets are
	 * dispatched to FQs via 'queue_id = hash % dist_size'. We expose the
	 * standard RETA API as an emulation that only accepts uniform patterns
	 * 'reta[i] = i % N' and translates them into a dpni_set_rx_hash_dist
	 * command with dist_size=N. See dpaa2_dev_rss_reta_update().
	 */
	dev_info->reta_size = DPAA2_RETA_SIZE;
	dev_info->hash_key_size = 0;

	dev_info->default_rxportconf.burst_size = dpaa2_dqrr_size;
	/* same is rx size for best perf */
	dev_info->default_txportconf.burst_size = dpaa2_dqrr_size;

	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_txportconf.ring_size = CONG_ENTER_TX_THRESHOLD;
	dev_info->default_rxportconf.ring_size = DPAA2_RX_DEFAULT_NBDESC;

	dev_info->speed_capa = priv->speed_capa;

	return 0;
}

static int
dpaa2_dev_rx_burst_mode_get(struct rte_eth_dev *dev,
	__rte_unused uint16_t queue_id,
	struct rte_eth_burst_mode *mode)
{
	eth_rx_burst_t pkt_burst = dev->rx_pkt_burst;

	if (pkt_burst == dpaa2_dev_prefetch_rx)
		snprintf(mode->info, sizeof(mode->info), "%s", "Scalar Prefetch");
	else if (pkt_burst == dpaa2_dev_rx)
		snprintf(mode->info, sizeof(mode->info), "%s", "Scalar");
	else if (pkt_burst == dpaa2_dev_loopback_rx)
		snprintf(mode->info, sizeof(mode->info), "%s", "Loopback");
	else
		return -EINVAL;

	return 0;
}

static int
dpaa2_dev_tx_burst_mode_get(struct rte_eth_dev *dev,
			__rte_unused uint16_t queue_id,
			struct rte_eth_burst_mode *mode)
{
	eth_tx_burst_t pkt_burst = dev->tx_pkt_burst;

	if (pkt_burst == dpaa2_dev_tx)
		snprintf(mode->info, sizeof(mode->info), "%s", "Scalar");
	else if (pkt_burst == dpaa2_dev_tx_ordered)
		snprintf(mode->info, sizeof(mode->info), "%s", "Ordered");
	else if (pkt_burst == rte_eth_pkt_burst_dummy)
		snprintf(mode->info, sizeof(mode->info), "%s", "Dummy");
	else
		return -EINVAL;

	return 0;
}

static int
dpaa2_alloc_rx_tx_queues(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	uint8_t num_queue_per_tc;
	struct dpaa2_queue *mc_q, *dpaa2_q;
	uint32_t tot_queues;
	int i, ret = 0;

	PMD_INIT_FUNC_TRACE();

	if (priv->tx_conf_type != DPAA2_TX_NO_CONF)
		tot_queues = priv->nb_rx_queues + 2 * priv->nb_tx_queues;
	else
		tot_queues = priv->nb_rx_queues + priv->nb_tx_queues;
	mc_q = rte_malloc(NULL, sizeof(struct dpaa2_queue) * tot_queues,
			  RTE_CACHE_LINE_SIZE);
	if (!mc_q) {
		DPAA2_PMD_ERR("Memory allocation failed for rx/tx queues");
		return -ENOBUFS;
	}

	num_queue_per_tc = (priv->nb_rx_queues / priv->num_rx_tc);
	for (i = 0; i < priv->nb_rx_queues; i++) {
		mc_q->eth_data = dev->data;
		mc_q->tc_index = i / num_queue_per_tc;
		mc_q->flow_id = i % num_queue_per_tc;
		mc_q->fqid = DPAA2_INVALID_FQ_ID;
		priv->rx_vq[i] = mc_q++;
		dpaa2_q = priv->rx_vq[i];
		ret = dpaa2_queue_storage_alloc(dpaa2_q,
			RTE_MAX_LCORE);
		if (ret)
			goto fail;
	}

	if (priv->flags & DPAA2_RX_ERROR_QUEUE_FLAG) {
		priv->rx_err_vq = rte_zmalloc("dpni_rx_err",
			sizeof(struct dpaa2_queue), 0);
		if (!priv->rx_err_vq) {
			ret = -ENOBUFS;
			goto fail;
		}

		dpaa2_q = priv->rx_err_vq;
		ret = dpaa2_queue_storage_alloc(dpaa2_q,
			RTE_MAX_LCORE);
		if (ret)
			goto fail;
	}

	num_queue_per_tc = (priv->nb_tx_queues / priv->num_tx_tc);
	for (i = 0; i < priv->nb_tx_queues; i++) {
		mc_q->eth_data = dev->data;
		mc_q->tc_index = i / num_queue_per_tc;
		mc_q->flow_id = i % num_queue_per_tc;
		mc_q->fqid = DPAA2_INVALID_FQ_ID;
		priv->tx_vq[i] = mc_q++;
		dpaa2_q = (struct dpaa2_queue *)priv->tx_vq[i];
		dpaa2_q->cscn = rte_malloc(NULL,
					   sizeof(struct qbman_result), 16);
		if (!dpaa2_q->cscn) {
			ret = -ENOBUFS;
			goto fail_tx;
		}
	}

	if (priv->tx_conf_type != DPAA2_TX_NO_CONF) {
		/*Setup tx confirmation queues*/
		for (i = 0; i < priv->nb_tx_queues; i++) {
			mc_q->eth_data = dev->data;
			mc_q->tc_index = i / num_queue_per_tc;
			mc_q->flow_id = i % num_queue_per_tc;
			mc_q->fqid = DPAA2_INVALID_FQ_ID;
			priv->tx_conf_vq[i] = mc_q++;
			dpaa2_q = priv->tx_conf_vq[i];
			ret = dpaa2_queue_storage_alloc(dpaa2_q,
					RTE_MAX_LCORE);
			if (ret)
				goto fail_tx_conf;
		}
	}

	return 0;
fail_tx_conf:
	i -= 1;
	while (i >= 0) {
		dpaa2_q = priv->tx_conf_vq[i];
		dpaa2_queue_storage_free(dpaa2_q, RTE_MAX_LCORE);
		priv->tx_conf_vq[i--] = NULL;
	}
	i = priv->nb_tx_queues;
fail_tx:
	i -= 1;
	while (i >= 0) {
		dpaa2_q = priv->tx_vq[i];
		rte_free(dpaa2_q->cscn);
		priv->tx_vq[i--] = NULL;
	}
	i = priv->nb_rx_queues;
fail:
	i -= 1;
	mc_q = priv->rx_vq[0];
	while (i >= 0) {
		dpaa2_q = priv->rx_vq[i];
		dpaa2_queue_storage_free(dpaa2_q, RTE_MAX_LCORE);
		priv->rx_vq[i--] = NULL;
	}

	if (priv->rx_err_vq) {
		dpaa2_q = priv->rx_err_vq;
		dpaa2_queue_storage_free(dpaa2_q, RTE_MAX_LCORE);
		rte_free(dpaa2_q);
		priv->rx_err_vq = NULL;
	}

	rte_free(mc_q);
	return ret;
}

static void
dpaa2_clear_queue_active_dps(struct dpaa2_queue *q, int num_lcores)
{
	int i;

	for (i = 0; i < num_lcores; i++) {
		struct queue_storage_info_t *qs = q->q_storage[i];

		if (!qs)
			continue;

		if (qs->active_dqs) {
			while (!qbman_check_command_complete(qs->active_dqs))
				continue; /* wait */

			clear_swp_active_dqs(qs->active_dpio_id);
			qs->active_dqs = NULL;
		}
	}
}

static void dpaa2_dev_rx_queue_intr_unbind(struct dpaa2_queue *dpaa2_q);

static void
dpaa2_free_rx_tx_queues(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_queue *dpaa2_q;
	int i;

	PMD_INIT_FUNC_TRACE();

	/* Queue allocation base */
	if (priv->rx_vq[0]) {
		/* Save base pointer before the loop NULLs rx_vq[] entries */
		void *mc_q = priv->rx_vq[0];

		/* cleaning up queue storage */
		for (i = 0; i < priv->nb_rx_queues; i++) {
			dpaa2_q = priv->rx_vq[i];
			if (dpaa2_q->napi_dpcon) {	/* release the rx-intr channel */
				dpaa2_dev_rx_queue_intr_unbind(dpaa2_q);
				rte_dpaa2_free_dpcon_dev(dpaa2_q->napi_dpcon);
				dpaa2_q->napi_dpcon = NULL;
				rte_atomic_store_explicit(&dpaa2_q->napi_sub_dpio,
						NULL, rte_memory_order_release);
			}
			dpaa2_clear_queue_active_dps(dpaa2_q,
						RTE_MAX_LCORE);
			dpaa2_queue_storage_free(dpaa2_q,
				RTE_MAX_LCORE);
			if (dpaa2_q->cfg)
				rte_free(dpaa2_q->cfg);
			dpaa2_q->cfg = NULL;
			priv->rx_vq[i] = NULL;
		}
		/* cleanup tx queue cscn */
		for (i = 0; i < priv->nb_tx_queues; i++) {
			dpaa2_q = priv->tx_vq[i];
			rte_free(dpaa2_q->cscn);
			priv->tx_vq[i] = NULL;
		}
		if (priv->tx_conf_type != DPAA2_TX_NO_CONF) {
			/* cleanup tx conf queue storage */
			for (i = 0; i < priv->nb_tx_queues; i++) {
				dpaa2_q = priv->tx_conf_vq[i];
				dpaa2_queue_storage_free(dpaa2_q,
					RTE_MAX_LCORE);
				priv->tx_conf_vq[i] = NULL;
			}
		}
		if (priv->rx_err_vq) {
			dpaa2_q = priv->rx_err_vq;
			dpaa2_queue_storage_free(dpaa2_q, RTE_MAX_LCORE);
			rte_free(dpaa2_q);
			priv->rx_err_vq = NULL;
		}

		/*free memory for all queues (RX+TX) */
		rte_free(mc_q);
	}
}

static int
dpaa2_dev_dcb_info(struct rte_eth_dev *dev,
	struct rte_eth_dcb_info *dcb_info)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	int i;

	if (!priv->nb_dcb_tcs)
		return -ENOTSUP;

	memset(dcb_info, 0, sizeof(struct rte_eth_dcb_info));
	dcb_info->nb_tcs = priv->nb_dcb_tcs;
	rte_memcpy(dcb_info->prio_tc, priv->prio_dcb_tc,
		sizeof(uint8_t) * RTE_ETH_DCB_NUM_USER_PRIORITIES);
	for (i = 0; i < dcb_info->nb_tcs; i++) {
		dcb_info->tc_queue.tc_rxq[0][i].base = priv->dist_queues * i;
		dcb_info->tc_queue.tc_rxq[0][i].nb_queue = priv->dist_queues;
	}

	return 0;
}

static int
dpaa2_eth_dev_configure(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	struct rte_eth_conf *eth_conf = &dev->data->dev_conf;
	uint64_t rx_offloads = eth_conf->rxmode.offloads;
	uint64_t tx_offloads = eth_conf->txmode.offloads;
	int rx_l3_csum_offload = false;
	int rx_l4_csum_offload = false;
	int tx_l3_csum_offload = false;
	int tx_l4_csum_offload = false;
	int ret, tc_index, nb_tcs;
	uint32_t max_rx_pktlen, base;
	struct rte_eth_rss_conf *rss_conf;
	struct rte_eth_dcb_rx_conf *dcb_rx_conf;
	struct rte_dpaa2_default_action_conf *def_act_conf;
	struct dpaa2_flow_tbl_profile *tbl_profile;

	PMD_INIT_FUNC_TRACE();

	/* interrupt mode is fixed once set; the queue count may still change */
	if (priv->intr_mode_set &&
	    priv->intr_mode != eth_conf->intr_conf.rxq) {
		DPAA2_PMD_ERR("Rx interrupt mode is fixed after configure; close the port to change it");
		return -ENOTSUP;
	}
	priv->intr_mode = eth_conf->intr_conf.rxq;
	priv->intr_mode_set = 1;

	/* Rx offloads which are enabled by default */
	if (dev_rx_offloads_nodis & ~rx_offloads) {
		DPAA2_PMD_INFO(
		"Some of rx offloads enabled by default - requested 0x%" PRIx64
		" fixed are 0x%" PRIx64,
		rx_offloads, dev_rx_offloads_nodis);
	}

	/* Tx offloads which are enabled by default */
	if (dev_tx_offloads_nodis & ~tx_offloads) {
		DPAA2_PMD_INFO(
		"Some of tx offloads enabled by default - requested 0x%" PRIx64
		" fixed are 0x%" PRIx64,
		tx_offloads, dev_tx_offloads_nodis);
	}

	max_rx_pktlen = eth_conf->rxmode.mtu + RTE_ETHER_HDR_LEN +
				RTE_ETHER_CRC_LEN + VLAN_TAG_SIZE;
	if (max_rx_pktlen <= DPAA2_MAX_RX_PKT_LEN) {
		ret = dpni_set_max_frame_length(dpni, CMD_PRI_LOW,
			priv->token, max_rx_pktlen - RTE_ETHER_CRC_LEN);
		if (ret != 0) {
			DPAA2_PMD_ERR("Unable to set mtu. check config");
			return ret;
		}
		DPAA2_PMD_DEBUG("MTU configured for the device: %d",
				dev->data->mtu);
	} else {
		DPAA2_PMD_ERR("Configured mtu %d and calculated max-pkt-len is %d which should be <= %d",
			eth_conf->rxmode.mtu, max_rx_pktlen, DPAA2_MAX_RX_PKT_LEN);
		return -1;
	}

	rss_conf = &eth_conf->rx_adv_conf.rss_conf;
	dcb_rx_conf = &eth_conf->rx_adv_conf.dcb_rx_conf;
	def_act_conf = eth_conf->rxmode.reserved_ptrs[0];

	for (tc_index = 0; tc_index < priv->num_rx_tc; tc_index++) {
		tbl_profile = &priv->flow_profile.tc_profile[tc_index];
		base = priv->dist_queues * tc_index;
		if (def_act_conf && tc_index < def_act_conf->max_tc) {
			if (def_act_conf->default_flows[tc_index] >= priv->dist_queues) {
				tbl_profile->default_drop = true;
			} else {
				tbl_profile->default_drop = false;
				tbl_profile->default_queue.index = base +
					def_act_conf->default_flows[tc_index];
			}
		}
		if (priv->fs_entries) {
			ret = dpaa2_setup_table_miss_action(dev, tc_index);
			if (ret) {
				DPAA2_PMD_ERR("Error(%d) to set miss action of %s-tc%d table",
					ret, dev->data->name, tc_index);
			}
		}
	}
	if (def_act_conf) {
		tbl_profile = &priv->flow_profile.qos_profile;
		if (def_act_conf->default_tc >= priv->num_rx_tc) {
			tbl_profile->default_drop = true;
		} else {
			tbl_profile->default_drop = false;
			tbl_profile->default_jump.group = def_act_conf->default_tc;
		}
	}
	ret = dpaa2_setup_table_miss_action(dev, priv->num_rx_tc);
	if (ret) {
		DPAA2_PMD_ERR("Error(%d) to set miss action of %s-QoS table",
			ret, dev->data->name);
	}

	if (eth_conf->rxmode.mq_mode & RTE_ETH_MQ_RX_RSS) {
		for (tc_index = 0; tc_index < priv->num_rx_tc; tc_index++) {
			ret = dpaa2_setup_flow_rss_dist(dev, rss_conf->rss_hf, tc_index);
			if (ret) {
				DPAA2_PMD_ERR("RSS dist on tc%d err(%d)", tc_index, ret);
				return ret;
			}
		}
	}

	if ((eth_conf->rxmode.mq_mode & RTE_ETH_MQ_RX_DCB) && priv->qos_entries) {
		nb_tcs = dcb_rx_conf->nb_tcs;
		for (tc_index = 0; tc_index < nb_tcs; tc_index++) {
			if (tc_index >= priv->num_rx_tc)
				break;
			ret = dpaa2_setup_flow_dcb_dist(dev, dcb_rx_conf->dcb_tc[tc_index],
				tc_index);
			if (ret) {
				DPAA2_PMD_ERR("DCB direct to tc%d err(%d)", tc_index, ret);
				return ret;
			}
		}
	}

	if (rx_offloads & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
		rx_l3_csum_offload = true;

	if ((rx_offloads & RTE_ETH_RX_OFFLOAD_UDP_CKSUM) ||
		(rx_offloads & RTE_ETH_RX_OFFLOAD_TCP_CKSUM) ||
		(rx_offloads & RTE_ETH_RX_OFFLOAD_SCTP_CKSUM))
		rx_l4_csum_offload = true;

	ret = dpni_set_offload(dpni, CMD_PRI_LOW, priv->token,
			       DPNI_OFF_RX_L3_CSUM, rx_l3_csum_offload);
	if (ret) {
		DPAA2_PMD_ERR("Error to set RX l3 csum:Error = %d", ret);
		return ret;
	}

	ret = dpni_set_offload(dpni, CMD_PRI_LOW, priv->token,
			       DPNI_OFF_RX_L4_CSUM, rx_l4_csum_offload);
	if (ret) {
		DPAA2_PMD_ERR("Error to get RX l4 csum:Error = %d", ret);
		return ret;
	}

	if (rx_offloads & RTE_ETH_RX_OFFLOAD_TIMESTAMP) {
		ret = rte_mbuf_dyn_rx_timestamp_register(&priv->rx_ts_offset,
			&priv->rx_ts_flag);
		if (ret) {
			DPAA2_PMD_ERR("Error to register timestamp field/flag");
			return ret;
		}
	}

	if (tx_offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
		tx_l3_csum_offload = true;

	if ((tx_offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) ||
		(tx_offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) ||
		(tx_offloads & RTE_ETH_TX_OFFLOAD_SCTP_CKSUM))
		tx_l4_csum_offload = true;

	ret = dpni_set_offload(dpni, CMD_PRI_LOW, priv->token,
			       DPNI_OFF_TX_L3_CSUM, tx_l3_csum_offload);
	if (ret) {
		DPAA2_PMD_ERR("Error to set TX l3 csum:Error = %d", ret);
		return ret;
	}

	ret = dpni_set_offload(dpni, CMD_PRI_LOW, priv->token,
			       DPNI_OFF_TX_L4_CSUM, tx_l4_csum_offload);
	if (ret) {
		DPAA2_PMD_ERR("Error to get TX l4 csum:Error = %d", ret);
		return ret;
	}

	/* Enabling hash results in FD requires setting DPNI_FLCTYPE_HASH in
	 * dpni_set_offload API. Setting this FLCTYPE for DPNI sets the FD[SC]
	 * to 0 for LS2 in the hardware thus disabling data/annotation
	 * stashing. For LX2 this is fixed in hardware and thus hash result and
	 * parse results can be received in FD using this option.
	 */
	if (dpaa2_svr_family == SVR_LX2160A) {
		ret = dpni_set_offload(dpni, CMD_PRI_LOW, priv->token,
				       DPNI_FLCTYPE_HASH, true);
		if (ret) {
			DPAA2_PMD_ERR("Error setting FLCTYPE: Err = %d", ret);
			return ret;
		}
	}

	if (rx_offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
		dpaa2_vlan_offload_set(dev, RTE_ETH_VLAN_FILTER_MASK);

	if (eth_conf->lpbk_mode) {
		ret = dpaa2_dev_recycle_config(dev);
		if (ret) {
			DPAA2_PMD_ERR("Error to configure %s to recycle port.",
				dev->data->name);

			return ret;
		}
	} else {
		/** User may disable loopback mode by calling
		 * "dev_configure" with lpbk_mode cleared.
		 * No matter the port was configured recycle or not,
		 * recycle de-configure is called here.
		 * If port is not recycled, the de-configure will return directly.
		 */
		ret = dpaa2_dev_recycle_deconfig(dev);
		if (ret) {
			DPAA2_PMD_ERR("Error to de-configure recycle port %s.",
				dev->data->name);

			return ret;
		}
	}

	/* allocate the intr handle once, sized to the queue ceiling; kept across
	 * reconfigure and freed at dev_close so the app epoll registration holds
	 */
	if (dev->data->dev_conf.intr_conf.rxq && dev->intr_handle == NULL) {
		dev->intr_handle = rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_PRIVATE);
		if (!dev->intr_handle ||
		    rte_intr_vec_list_alloc(dev->intr_handle, "rxq_intr",
				priv->nb_rx_queues) ||
		    rte_intr_nb_efd_set(dev->intr_handle, priv->nb_rx_queues) ||
		    rte_intr_type_set(dev->intr_handle, RTE_INTR_HANDLE_EXT)) {
			DPAA2_PMD_ERR("Failed to set up rx-queue interrupts");
			/* capture the error before cleanup may clobber rte_errno */
			ret = rte_errno ? -rte_errno : -EIO;
			if (dev->intr_handle) {
				rte_intr_vec_list_free(dev->intr_handle);
				rte_intr_instance_free(dev->intr_handle);
				dev->intr_handle = NULL;
			}
			return ret;
		}
	}

	dpaa2_tm_init(dev);

	return 0;
}

/* Function to setup RX flow information. It contains traffic class ID,
 * flow ID, destination configuration etc.
 */
static int
dpaa2_dev_rx_queue_setup(struct rte_eth_dev *dev,
	uint16_t rx_queue_id,
	uint16_t nb_rx_desc,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_rxconf *rx_conf,
	struct rte_mempool *mb_pool)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	bool dpcon_allocated = false;
	struct dpaa2_queue *dpaa2_q;
	struct dpni_queue *cfg;
	struct dpni_taildrop taildrop;
	uint8_t qopt = 0;
	uint16_t flow_id;
	uint32_t bpid;
	int ret, ops_idx;

	PMD_INIT_FUNC_TRACE();

	DPAA2_PMD_DEBUG("dev =%p, queue =%d, pool = %p, conf =%p",
			dev, rx_queue_id, mb_pool, rx_conf);

	/* Rx deferred start is not supported */
	if (rx_conf->rx_deferred_start) {
		DPAA2_PMD_ERR("%s: Rx deferred start not supported",
			dev->data->name);
		return -EINVAL;
	}

	total_nb_rx_desc += nb_rx_desc;
	if (total_nb_rx_desc > MAX_NB_RX_DESC_IN_PEB &&
	    (priv->options & DPNI_OPT_V1_PFDR_IN_PEB)) {
		DPAA2_PMD_WARN("RX descriptor exceeds limit(%d) to load PFDR in PEB",
			       MAX_NB_RX_DESC_IN_PEB);
		DPAA2_PMD_WARN("Suggest removing 0x%08x from DPNI creating options(0x%08x)",
			       DPNI_OPT_V1_PFDR_IN_PEB, priv->options);
		DPAA2_PMD_WARN("Or reduce RX descriptor number(%d) per queue",
			       nb_rx_desc);
	}

	dpaa2_q = priv->rx_vq[rx_queue_id];
	if (dpaa2_q->fqid != DPAA2_INVALID_FQ_ID) {
		DPAA2_PMD_WARN("%s: RXQ[%d] has been setup",
			dev->data->name, rx_queue_id);
		dev->data->rx_queues[rx_queue_id] = dpaa2_q;
		return 0;
	}

	ops_idx = rte_dpaa2_mpool_get_ops_idx();
	if (ops_idx != mb_pool->ops_index) {
		DPAA2_PMD_ERR("MP(%s)'s ops index(%d) != %d",
			mb_pool->name, mb_pool->ops_index, ops_idx);
		return -EINVAL;
	}

	if (!priv->bp_list || priv->bp_list->mp != mb_pool) {
		if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
			ret = rte_dpaa2_bpid_info_init(mb_pool);
			if (ret)
				return ret;
		}
		bpid = mempool_to_bpid(mb_pool);
		ret = dpaa2_attach_bp_list(priv, dpni,
				rte_dpaa2_bpid_info[bpid].bp_list,
				dpaa2_q->tc_index);
		if (ret)
			return ret;
	}
	cfg = rte_zmalloc(NULL, sizeof(struct dpni_queue), 0);
	if (!cfg)
		return -ENOMEM;
	dpaa2_q->cfg = cfg;
	dpaa2_q->mb_pool = mb_pool; /**< mbuf pool to populate RX ring. */
	dpaa2_q->bp_array = rte_dpaa2_bpid_info;
	dpaa2_q->offloads = rx_conf->offloads;

	/* NAPI: grab a DPCON channel so dev_start can bind this FQ statically.
	 * The DQRR burst replaces the poll path for every queue at once, so a
	 * missing channel is fatal rather than a silent per-queue fallback.
	 */
	rte_atomic_store_explicit(&dpaa2_q->napi_sub_dpio, NULL,
			rte_memory_order_release);
	if (dev->data->dev_conf.intr_conf.rxq && !dpaa2_q->napi_dpcon) {
		dpaa2_q->napi_dpcon = rte_dpaa2_alloc_dpcon_dev();
		if (!dpaa2_q->napi_dpcon) {
			DPAA2_PMD_ERR("rxq %d: no DPCON for rx-queue interrupts",
				      rx_queue_id);
			return -ENODEV;
		}
		dpcon_allocated = true;
		/* the DPCON must be enabled to generate CDAN notifications */
		ret = dpcon_enable(&dpaa2_q->napi_dpcon->dpcon, CMD_PRI_LOW,
				   dpaa2_q->napi_dpcon->token);
		if (ret) {
			DPAA2_PMD_ERR("rxq %d: dpcon_enable: %d", rx_queue_id, ret);
			goto err_free_dpcon;
		}
	}

	/*Get the flow id from given VQ id*/
	flow_id = dpaa2_q->flow_id;
	memset(cfg, 0, sizeof(struct dpni_queue));

	qopt |= DPNI_QUEUE_OPT_USER_CTX;
	cfg->user_context = (size_t)(dpaa2_q);

	/* napi: schedule the FQ to its DPCON once, when the channel is first
	 * grabbed; never re-bound (the MC refuses scheduled->parked at runtime)
	 */
	if (dpcon_allocated) {
		qopt |= DPNI_QUEUE_OPT_DEST;
		cfg->destination.type = DPNI_DEST_DPCON;
		cfg->destination.id = dpaa2_q->napi_dpcon->dpcon_id;
	}

	/** RXQs in same TC share same cgid.*/
	if (dpaa2_q->tc_index < priv->max_cgs) {
		qopt |= DPNI_QUEUE_OPT_SET_CGID;
		cfg->cgid = dpaa2_q->tc_index;
		priv->cgid_in_use[dpaa2_q->tc_index]++;
	} else {
		cfg->cgid = DPAA2_INVALID_CGID;
	}

	/*if ls2088 or rev2 device, enable the stashing */

	if ((dpaa2_svr_family & 0xffff0000) != SVR_LS2080A) {
		qopt |= DPNI_QUEUE_OPT_FLC;
		cfg->flc.stash_control = true;
		dpaa2_flc_stashing_clear_all(&cfg->flc.value);
		if (priv->flags & DPAA2_RX_DATA_STASHING_OFF_FLAG) {
			dpaa2_flc_stashing_set(DPAA2_FLC_DATA_STASHING, 0,
				&cfg->flc.value);
			dpaa2_q->data_stashing_off = 1;
		} else {
			dpaa2_flc_stashing_set(DPAA2_FLC_DATA_STASHING, 1,
				&cfg->flc.value);
			dpaa2_q->data_stashing_off = 0;
		}
		if ((dpaa2_svr_family & 0xffff0000) != SVR_LX2160A) {
			dpaa2_flc_stashing_set(DPAA2_FLC_ANNO_STASHING, 1,
				&cfg->flc.value);
		}
	}

	ret = dpni_set_queue(dpni, CMD_PRI_LOW, priv->token, DPNI_QUEUE_RX,
			dpaa2_q->tc_index, flow_id, qopt, cfg);
	if (ret) {
		rte_free(dpaa2_q->cfg);
		dpaa2_q->cfg = NULL;
		DPAA2_PMD_ERR("Error in setting the rx flow: = %d", ret);
		goto err_free_dpcon;
	}

	dpaa2_q->nb_desc = nb_rx_desc;
	memset(&taildrop, 0, sizeof(struct dpni_taildrop));
	if (!(priv->flags & DPAA2_RX_TAILDROP_OFF))
		taildrop.enable = 1;
	/* Private CGR will use tail drop length as nb_rx_desc * queues per TC.
	 * For rest cases we can use standard byte based tail drop.
	 * There is no HW restriction, but number of CGRs are limited,
	 * hence this restriction is placed.
	 */
	if (cfg->cgid != DPAA2_INVALID_CGID &&
		priv->cgid_in_use[dpaa2_q->tc_index] == 1) {
		/*enabling per TC congestion control */
		taildrop.threshold = nb_rx_desc * priv->dist_queues;
		taildrop.units = DPNI_CONGESTION_UNIT_FRAMES;
		taildrop.oal = 0;
		DPAA2_PMD_DEBUG("%s CG Tail Drop on TC%d",
			taildrop.enable ? "Enabling" : "Disabling",
			dpaa2_q->tc_index);
		ret = dpni_set_taildrop(dpni, CMD_PRI_LOW, priv->token,
			DPNI_CP_CONGESTION_GROUP, DPNI_QUEUE_RX,
			dpaa2_q->tc_index, cfg->cgid, &taildrop);
	} else if (cfg->cgid == DPAA2_INVALID_CGID) {
		/*enabling per rx queue congestion control */
		taildrop.threshold = CONG_THRESHOLD_RX_BYTES_Q;
		taildrop.units = DPNI_CONGESTION_UNIT_BYTES;
		taildrop.oal = CONG_RX_OAL;
		DPAA2_PMD_DEBUG("%s Byte based Drop on TC[%d].flow%d",
			taildrop.enable ? "Enabling" : "Disabling",
			dpaa2_q->tc_index, flow_id);
		ret = dpni_set_taildrop(dpni, CMD_PRI_LOW, priv->token,
			DPNI_CP_QUEUE, DPNI_QUEUE_RX,
			dpaa2_q->tc_index, flow_id, &taildrop);
	}
	if (ret) {
		rte_free(dpaa2_q->cfg);
		dpaa2_q->cfg = NULL;
		DPAA2_PMD_ERR("Error in setting taildrop. err=(%d)", ret);
		return ret;
	}

	dpaa2_q->options = qopt;

	dev->data->rx_queues[rx_queue_id] = dpaa2_q;
	return 0;

err_free_dpcon:
	/* free only the DPCON this call allocated; a pre-existing one belongs to
	 * an earlier setup and is released at dev_close
	 */
	if (dpcon_allocated) {
		rte_dpaa2_free_dpcon_dev(dpaa2_q->napi_dpcon);
		dpaa2_q->napi_dpcon = NULL;
	}
	return ret;
}

static int
dpaa2_dev_tx_queue_setup(struct rte_eth_dev *dev,
	uint16_t tx_queue_id,
	uint16_t nb_tx_desc,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_txconf *tx_conf)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_queue *dpaa2_q = priv->tx_vq[tx_queue_id];
	struct dpaa2_queue *dpaa2_tx_conf_q = priv->tx_conf_vq[tx_queue_id];
	struct fsl_mc_io *dpni = dev->process_private;
	struct dpni_queue tx_conf_cfg;
	struct dpni_queue tx_flow_cfg;
	uint8_t qopt = 0;
	uint16_t channel_id, flow_id;
	struct dpni_queue_id qid;
	uint32_t tc_id;
	int ret;
	uint64_t iova;

	PMD_INIT_FUNC_TRACE();

	/* Tx deferred start is not supported */
	if (tx_conf->tx_deferred_start) {
		DPAA2_PMD_ERR("%s:Tx deferred start not supported",
			dev->data->name);
		return -EINVAL;
	}

	dpaa2_q->nb_desc = UINT16_MAX;
	dpaa2_q->offloads = tx_conf->offloads;

	/* Return if queue already configured */
	if (dpaa2_q->fqid != DPAA2_INVALID_FQ_ID) {
		DPAA2_PMD_WARN("%s: TXQ[%d] has been setup",
			dev->data->name, tx_queue_id);
		dev->data->tx_queues[tx_queue_id] = dpaa2_q;
		return 0;
	}

	memset(&tx_conf_cfg, 0, sizeof(struct dpni_queue));
	memset(&tx_flow_cfg, 0, sizeof(struct dpni_queue));

	tc_id = dpaa2_q->tc_index;
	flow_id = dpaa2_q->flow_id;
	if (tc_id < priv->num_channels)
		channel_id = priv->tx_channels[tc_id];
	else
		channel_id = priv->tx_channels[priv->num_channels - 1];

	ret = dpni_set_queue(dpni, CMD_PRI_LOW, priv->token, DPNI_QUEUE_TX,
			DPNI_BUILD_PARAM(channel_id, tc_id), flow_id, qopt, &tx_flow_cfg);
	if (ret) {
		DPAA2_PMD_ERR("Failed(%d) to set %s's TC[%d].txq[%d]",
			ret, dev->data->name, tc_id, flow_id);
		return ret;
	}

	ret = dpni_get_queue(dpni, CMD_PRI_LOW, priv->token,
			DPNI_QUEUE_TX, DPNI_BUILD_PARAM(channel_id, tc_id),
			dpaa2_q->flow_id, &tx_flow_cfg, &qid);
	if (ret) {
		DPAA2_PMD_ERR("Error in getting LFQID err=%d", ret);
		return ret;
	}
	dpaa2_q->fqid = qid.fqid;

	if (!(priv->flags & DPAA2_TX_CGR_OFF)) {
		struct dpni_congestion_notification_cfg cong_notif_cfg = {0};

		dpaa2_q->nb_desc = nb_tx_desc;

		cong_notif_cfg.units = DPNI_CONGESTION_UNIT_FRAMES;
		cong_notif_cfg.threshold_entry = nb_tx_desc;
		/* Notify that the queue is not congested when the data in
		 * the queue is below this threshold.(90% of value)
		 */
		cong_notif_cfg.threshold_exit = (nb_tx_desc * 9) / 10;
		cong_notif_cfg.message_ctx = 0;

		iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(dpaa2_q->cscn,
			sizeof(struct qbman_result));
		if (iova == RTE_BAD_IOVA) {
			DPAA2_PMD_ERR("No IOMMU map for cscn(%p)(size=%x)",
				dpaa2_q->cscn, (uint32_t)sizeof(struct qbman_result));

			return -ENOBUFS;
		}

		cong_notif_cfg.message_iova = iova;
		cong_notif_cfg.dest_cfg.dest_type = DPNI_DEST_NONE;
		cong_notif_cfg.notification_mode =
					 DPNI_CONG_OPT_WRITE_MEM_ON_ENTER |
					 DPNI_CONG_OPT_WRITE_MEM_ON_EXIT |
					 DPNI_CONG_OPT_COHERENT_WRITE;
		cong_notif_cfg.cg_point = DPNI_CP_QUEUE;

		ret = dpni_set_congestion_notification(dpni,
				CMD_PRI_LOW, priv->token, DPNI_QUEUE_TX,
				DPNI_BUILD_PARAM(channel_id, tc_id), &cong_notif_cfg);
		if (ret) {
			DPAA2_PMD_ERR("Set TX congestion notification err=%d", ret);
			return ret;
		}
	}
	dpaa2_q->cb_eqresp_free = dpaa2_dev_free_eqresp_buf;
	dev->data->tx_queues[tx_queue_id] = dpaa2_q;

	if (priv->tx_conf_type != DPAA2_TX_NO_CONF) {
		tc_id = dpaa2_tx_conf_q->tc_index;
		flow_id = dpaa2_tx_conf_q->flow_id;
		dpaa2_q->tx_conf_queue = dpaa2_tx_conf_q;
		qopt |= DPNI_QUEUE_OPT_USER_CTX;
		tx_conf_cfg.user_context = (size_t)(dpaa2_q);
		ret = dpni_set_queue(dpni, CMD_PRI_LOW, priv->token,
				DPNI_QUEUE_TX_CONFIRM,
				DPNI_BUILD_PARAM(channel_id, tc_id),
				flow_id, qopt, &tx_conf_cfg);
		if (ret) {
			DPAA2_PMD_ERR("Set TC[%d].TX[%d] conf flow err=%d",
				tc_id, flow_id, ret);
			return ret;
		}

		ret = dpni_get_queue(dpni, CMD_PRI_LOW, priv->token,
				DPNI_QUEUE_TX_CONFIRM,
				DPNI_BUILD_PARAM(channel_id, tc_id),
				flow_id, &tx_conf_cfg, &qid);
		if (ret) {
			DPAA2_PMD_ERR("Error in getting LFQID err=%d", ret);
			return ret;
		}
		dpaa2_tx_conf_q->fqid = qid.fqid;
	}

	return 0;
}

/* drop a queue's worker portal reference; the FQ stays scheduled to its DPCON
 * (only dpni_reset at close un-schedules it). Teardown only.
 */
static void
dpaa2_dev_rx_queue_intr_unbind(struct dpaa2_queue *dpaa2_q)
{
	if (!dpaa2_q || !dpaa2_q->napi_dpcon)
		return;

	/* the portal (CDAN, DQRI) can only be torn down on the polling lcore;
	 * warn if the app skipped rte_eth_dev_rx_intr_disable() before stop/close
	 */
	if (dpaa2_q->napi_armed)
		DPAA2_PMD_WARN("rxq flow %u freed while armed; call "
			       "rte_eth_dev_rx_intr_disable() on the polling "
			       "lcore before stop/close", dpaa2_q->flow_id);

	/* CDAN and DQRI teardown is the worker's job via rte_eth_dev_rx_intr_disable() */
	rte_atomic_store_explicit(&dpaa2_q->napi_sub_dpio, NULL,
			rte_memory_order_release);
}

static void
dpaa2_dev_rx_queue_release(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	struct dpaa2_queue *dpaa2_q = dev->data->rx_queues[rx_queue_id];
	struct dpaa2_dev_priv *priv = dpaa2_q->eth_data->dev_private;
	struct fsl_mc_io *dpni = priv->eth_dev->process_private;
	uint8_t qopt = 0;
	int ret;
	struct dpni_queue *cfg = dpaa2_q->cfg;

	PMD_INIT_FUNC_TRACE();

	total_nb_rx_desc -= dpaa2_q->nb_desc;

	if (cfg) {
		if (cfg->cgid != DPAA2_INVALID_CGID) {
			qopt = DPNI_QUEUE_OPT_CLEAR_CGID;
			ret = dpni_set_queue(dpni, CMD_PRI_LOW, priv->token,
				DPNI_QUEUE_RX, dpaa2_q->tc_index, dpaa2_q->flow_id,
				qopt, cfg);
			if (ret) {
				DPAA2_PMD_ERR("Unable to clear CGR from TC[%d].flow%d err=%d",
					dpaa2_q->tc_index, dpaa2_q->flow_id, ret);
			}
			priv->cgid_in_use[cfg->cgid]--;
		}
		rte_free(cfg);
		dpaa2_q->cfg = NULL;
	}
	/* keep the DPCON on the FQ across a reconfigure; freed at dev_close */
	if (dpaa2_q->napi_dpcon)
		dpaa2_dev_rx_queue_intr_unbind(dpaa2_q);
}

static int
dpaa2_dev_rx_queue_count(void *rx_queue)
{
	int32_t ret;
	struct dpaa2_queue *dpaa2_q;
	struct qbman_swp *swp;
	struct qbman_fq_query_np_rslt state;
	uint32_t frame_cnt = 0;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_PMD_ERR(
				"Failed to allocate IO portal, tid: %d",
				rte_gettid());
			return -EINVAL;
		}
	}
	swp = DPAA2_PER_LCORE_PORTAL;

	dpaa2_q = rx_queue;

	if (qbman_fq_query_state(swp, dpaa2_q->fqid, &state) == 0) {
		frame_cnt = qbman_fq_state_frame_count(&state);
		DPAA2_PMD_DP_DEBUG("RX frame count for q(%p) is %u",
				rx_queue, frame_cnt);
	}
	return frame_cnt;
}

static const uint32_t *
dpaa2_supported_ptypes_get(struct rte_eth_dev *dev, size_t *no_of_elements)
{
	static const uint32_t ptypes[] = {
		/*todo -= add more types */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_ICMP,
	};

	if (dev->rx_pkt_burst == dpaa2_dev_prefetch_rx ||
		dev->rx_pkt_burst == dpaa2_dev_rx ||
		dev->rx_pkt_burst == dpaa2_dev_loopback_rx ||
		dev->rx_pkt_burst == dpaa2_dev_rx_channel ||
		dev->rx_pkt_burst == dpaa2_dev_prefetch_rx_channel) {
		*no_of_elements = RTE_DIM(ptypes);
		return ptypes;
	}
	return NULL;
}

/**
 * Dpaa2 link Interrupt handler
 *
 * @param param
 *  The address of parameter (struct rte_eth_dev *) registered before.
 *
 * @return
 *  void
 */
static void
dpaa2_interrupt_handler(void *param)
{
	struct rte_eth_dev *dev = param;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;
	int ret;
	int irq_index = DPNI_IRQ_INDEX;
	unsigned int status = 0, clear = 0;

	PMD_INIT_FUNC_TRACE();

	if (dpni == NULL) {
		DPAA2_PMD_ERR("dpni is NULL");
		return;
	}

	ret = dpni_get_irq_status(dpni, CMD_PRI_LOW, priv->token,
				  irq_index, &status);
	if (unlikely(ret)) {
		DPAA2_PMD_ERR("Can't get irq status (err %d)", ret);
		clear = 0xffffffff;
		goto out;
	}

	if (status & DPNI_IRQ_EVENT_LINK_CHANGED) {
		clear = DPNI_IRQ_EVENT_LINK_CHANGED;
		dpaa2_dev_link_update(dev, 0);
		/* calling all the apps registered for link status event */
		rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL);
	}
out:
	ret = dpni_clear_irq_status(dpni, CMD_PRI_LOW, priv->token,
				    irq_index, clear);
	if (unlikely(ret))
		DPAA2_PMD_ERR("Can't clear irq status (err %d)", ret);
}

static int
dpaa2_eth_setup_irqs(struct rte_eth_dev *dev, int enable)
{
	int err = 0;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;
	int irq_index = DPNI_IRQ_INDEX;
	unsigned int mask = DPNI_IRQ_EVENT_LINK_CHANGED;

	PMD_INIT_FUNC_TRACE();

	err = dpni_set_irq_mask(dpni, CMD_PRI_LOW, priv->token,
				irq_index, mask);
	if (err < 0) {
		DPAA2_PMD_ERR("Error: dpni_set_irq_mask():%d (%s)", err,
			      strerror(-err));
		return err;
	}

	err = dpni_set_irq_enable(dpni, CMD_PRI_LOW, priv->token,
				  irq_index, enable);
	if (err < 0)
		DPAA2_PMD_ERR("Error: dpni_set_irq_enable():%d (%s)", err,
			      strerror(-err));

	return err;
}

static int
dpaa2_dev_start(struct rte_eth_dev *dev)
{
	struct rte_dpaa2_device *dpaa2_dev;
	struct rte_eth_dev_data *data = dev->data;
	struct dpaa2_dev_priv *priv = data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;
	struct dpni_queue cfg;
	struct dpni_error_cfg	err_cfg;
	struct dpni_queue_id qid;
	struct dpaa2_queue *dpaa2_q;
	int ret, i;
	struct rte_intr_handle *intr_handle;

	dpaa2_dev = RTE_CLASS_TO_BUS_DEVICE(dev, *dpaa2_dev);
	intr_handle = dpaa2_dev->intr_handle;

	PMD_INIT_FUNC_TRACE();

	/* napi: FQs are scheduled to their DPCON at rx_queue_setup, not here; just
	 * select the channel burst (the worker subscribes its portal later)
	 */
	if (dev->data->dev_conf.intr_conf.rxq) {
		for (i = 0; i < data->nb_rx_queues; i++) {
			dpaa2_q = data->rx_queues[i];
			/* the channel burst below derefs napi_dpcon, so every
			 * rx queue must own a channel
			 */
			if (!dpaa2_q->napi_dpcon) {
				DPAA2_PMD_ERR("napi: rxq %d has no DPCON channel", i);
				return -ENODEV;
			}
		}
		if (priv->flags & DPAA2_NO_PREFETCH_RX)
			dev->rx_pkt_burst = dpaa2_dev_rx_channel;
		else
			dev->rx_pkt_burst = dpaa2_dev_prefetch_rx_channel;
	}

	ret = dpni_enable(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		DPAA2_PMD_ERR("Failure in enabling dpni %d device: err=%d",
			      priv->hw_id, ret);
		return ret;
	}

	for (i = 0; i < data->nb_rx_queues; i++) {
		dpaa2_q = data->rx_queues[i];
		ret = dpni_get_queue(dpni, CMD_PRI_LOW, priv->token,
				DPNI_QUEUE_RX, dpaa2_q->tc_index,
				dpaa2_q->flow_id, &cfg, &qid);
		if (ret) {
			DPAA2_PMD_ERR("Error in getting flow information: "
				      "err=%d", ret);
			return ret;
		}
		dpaa2_q->fqid = qid.fqid;
	}

	if (priv->flags & DPAA2_RX_ERROR_QUEUE_FLAG) {
		ret = dpni_get_queue(dpni, CMD_PRI_LOW, priv->token,
				     DPNI_QUEUE_RX_ERR, 0, 0, &cfg, &qid);
		if (ret) {
			DPAA2_PMD_ERR("Error getting rx err flow information: err=%d",
						ret);
			return ret;
		}
		dpaa2_q = priv->rx_err_vq;
		dpaa2_q->fqid = qid.fqid;
		dpaa2_q->eth_data = dev->data;

		err_cfg.errors =  DPNI_ERROR_DISC;
		err_cfg.error_action = DPNI_ERROR_ACTION_SEND_TO_ERROR_QUEUE;
	} else {
		/* checksum errors, send them to normal path
		 * and set it in annotation
		 */
		err_cfg.errors = DPNI_ERROR_L3CE | DPNI_ERROR_L4CE;

		/* if packet with parse error are not to be dropped */
		if (!(priv->flags & DPAA2_PARSE_ERR_DROP))
			err_cfg.errors |= DPNI_ERROR_PHE | DPNI_ERROR_BLE;

		err_cfg.error_action = DPNI_ERROR_ACTION_CONTINUE;
	}
	err_cfg.set_frame_annotation = true;

	ret = dpni_set_errors_behavior(dpni, CMD_PRI_LOW,
				       priv->token, &err_cfg);
	if (ret) {
		DPAA2_PMD_ERR("Error to dpni_set_errors_behavior: code = %d",
			      ret);
		return ret;
	}

	/* if the interrupts were configured on this devices*/
	if (intr_handle && rte_intr_fd_get(intr_handle) &&
	    dev->data->dev_conf.intr_conf.lsc != 0) {
		/* Registering LSC interrupt handler */
		rte_intr_callback_register(intr_handle,
					   dpaa2_interrupt_handler,
					   (void *)dev);

		/* enable vfio intr/eventfd mapping
		 * Interrupt index 0 is required, so we can not use
		 * rte_intr_enable.
		 */
		rte_dpaa2_intr_enable(intr_handle, DPNI_IRQ_INDEX);

		/* enable dpni_irqs */
		dpaa2_eth_setup_irqs(dev, 1);
	}

	/* Power up the phy. Needed to make the link go UP.
	 * Called after LSC interrupt setup so that the link-up
	 * event is not missed if the MAC negotiates quickly.
	 */
	dpaa2_dev_set_link_up(dev);

	/* Change the tx burst function if ordered queues are used */
	if (priv->en_ordered)
		dev->tx_pkt_burst = dpaa2_dev_tx_ordered;

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

/**
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC.
 */
static int
dpaa2_dev_stop(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	int ret;
	struct rte_eth_link link;
	struct rte_intr_handle *intr_handle;
	struct rte_dpaa2_device *dpaa2_dev;
	uint16_t i;

	dpaa2_dev = RTE_CLASS_TO_BUS_DEVICE(dev, *dpaa2_dev);
	intr_handle = dpaa2_dev->intr_handle;

	PMD_INIT_FUNC_TRACE();

	/* reset interrupt callback  */
	if (intr_handle && rte_intr_fd_get(intr_handle) &&
	    dev->data->dev_conf.intr_conf.lsc != 0) {
		/*disable dpni irqs */
		dpaa2_eth_setup_irqs(dev, 0);

		/* disable vfio intr before callback unregister */
		rte_dpaa2_intr_disable(intr_handle, DPNI_IRQ_INDEX);

		/* Unregistering LSC interrupt handler */
		rte_intr_callback_unregister(intr_handle,
					     dpaa2_interrupt_handler,
					     (void *)dev);
	}

	dpaa2_dev_set_link_down(dev);

	ret = dpni_disable(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		DPAA2_PMD_ERR("Failure (ret %d) in disabling dpni %d dev",
			      ret, priv->hw_id);
		return ret;
	}

	/* clear the recorded link status */
	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	return 0;
}

static int
dpaa2_dev_close(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	int i, ret;
	struct rte_eth_link link;
	struct dpaa2_flow_tbl_profile *tbl_profile;

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	if (!dpni) {
		DPAA2_PMD_WARN("Already closed or not started");
		return -EINVAL;
	}

	dpaa2_tm_deinit(dev);
	dpaa2_flow_clean(dev, MAX_TCS);
	/** No matter dcb flows are created or not, they are destroyed in flow clean.*/
	memset(priv->dcb_flow, 0, sizeof(void *) * RTE_ETH_DCB_NUM_USER_PRIORITIES);
	/* Clean the device first */
	ret = dpni_reset(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		DPAA2_PMD_ERR("Failure cleaning dpni device: err=%d", ret);
		return ret;
	}

	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);

	/* Free private queues memory */
	dpaa2_free_rx_tx_queues(dev);
	/* release the rx-queue interrupt vector and instance allocated at
	 * dev_configure (configure/close pair); the per-queue CDAN and portal
	 * teardown is the worker's job via rte_eth_dev_rx_intr_disable().
	 */
	if (dev->intr_handle) {
		rte_intr_vec_list_free(dev->intr_handle);
		rte_intr_instance_free(dev->intr_handle);
		dev->intr_handle = NULL;
	}
	/* Close the device at underlying layer*/
	ret = dpni_close(dpni, CMD_PRI_LOW, priv->token);
	if (ret) {
		DPAA2_PMD_ERR("Failure closing dpni device with err code %d",
			ret);
	}

	/* Free the allocated memory for ethernet private data and dpni*/
	priv->hw = NULL;
	dev->process_private = NULL;
	rte_free(dpni);

	for (i = 0; i < (MAX_TCS + 1); i++) {
		if (i < MAX_TCS)
			tbl_profile = &priv->flow_profile.tc_profile[i];
		else
			tbl_profile = &priv->flow_profile.qos_profile;
		rte_free(tbl_profile->extract_param);
		tbl_profile->extract_param = NULL;
		rte_free(tbl_profile->entry_map);
		tbl_profile->entry_map = NULL;
	}

	rte_free(priv->cnt_idx_dma_mem);
	rte_free(priv->cnt_values_dma_mem);
	priv->cnt_idx_dma_mem = NULL;
	priv->cnt_values_dma_mem = NULL;

	DPAA2_PMD_INFO("%s: netdev deleted", dev->data->name);
	return 0;
}

static int
dpaa2_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;

	PMD_INIT_FUNC_TRACE();

	if (dpni == NULL) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -ENODEV;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, priv->token, true);
	if (ret < 0)
		DPAA2_PMD_ERR("Unable to enable U promisc mode %d", ret);

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, priv->token, true);
	if (ret < 0)
		DPAA2_PMD_ERR("Unable to enable M promisc mode %d", ret);

	return ret;
}

static int
dpaa2_dev_promiscuous_disable(
		struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;

	PMD_INIT_FUNC_TRACE();

	if (dpni == NULL) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -ENODEV;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, priv->token, false);
	if (ret < 0)
		DPAA2_PMD_ERR("Unable to disable U promisc mode %d", ret);

	if (dev->data->all_multicast == 0) {
		ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW,
						 priv->token, false);
		if (ret < 0)
			DPAA2_PMD_ERR("Unable to disable M promisc mode %d",
				      ret);
	}

	return ret;
}

static int
dpaa2_dev_allmulticast_enable(
		struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;

	PMD_INIT_FUNC_TRACE();

	if (dpni == NULL) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -ENODEV;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, priv->token, true);
	if (ret < 0)
		DPAA2_PMD_ERR("Unable to enable multicast mode %d", ret);

	return ret;
}

static int
dpaa2_dev_allmulticast_disable(struct rte_eth_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;

	PMD_INIT_FUNC_TRACE();

	if (dpni == NULL) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -ENODEV;
	}

	/* must remain on for all promiscuous */
	if (dev->data->promiscuous == 1)
		return 0;

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, priv->token, false);
	if (ret < 0)
		DPAA2_PMD_ERR("Unable to disable multicast mode %d", ret);

	return ret;
}

static int
dpaa2_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	uint32_t frame_size = mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN
				+ VLAN_TAG_SIZE;

	PMD_INIT_FUNC_TRACE();

	if (!dpni) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -EINVAL;
	}

	/* Set the Max Rx frame length as 'mtu' +
	 * Maximum Ethernet header length
	 */
	ret = dpni_set_max_frame_length(dpni, CMD_PRI_LOW, priv->token,
					frame_size - RTE_ETHER_CRC_LEN);
	if (ret) {
		DPAA2_PMD_ERR("Setting the max frame length failed");
		return ret;
	}
	dev->data->mtu = mtu;
	DPAA2_PMD_INFO("MTU configured for the device: %d", mtu);
	return 0;
}

static int
dpaa2_dev_add_mac_addr(struct rte_eth_dev *dev,
	struct rte_ether_addr *addr,
	__rte_unused uint32_t index,
	__rte_unused uint32_t pool)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;

	PMD_INIT_FUNC_TRACE();

	if (dpni == NULL) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -EINVAL;
	}

	ret = dpni_add_mac_addr(dpni, CMD_PRI_LOW, priv->token,
				addr->addr_bytes, 0, 0, 0);
	if (ret)
		DPAA2_PMD_ERR("ERR(%d) Adding the MAC ADDR failed", ret);
	return ret;
}

static void
dpaa2_dev_remove_mac_addr(struct rte_eth_dev *dev,
	uint32_t index)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	struct rte_eth_dev_data *data = dev->data;
	struct rte_ether_addr *macaddr;

	PMD_INIT_FUNC_TRACE();

	macaddr = &data->mac_addrs[index];

	if (!dpni) {
		DPAA2_PMD_ERR("dpni is NULL");
		return;
	}

	ret = dpni_remove_mac_addr(dpni, CMD_PRI_LOW,
				   priv->token, macaddr->addr_bytes);
	if (ret)
		DPAA2_PMD_ERR(
			"error: Removing the MAC ADDR failed: err = %d", ret);
}

static int
dpaa2_dev_set_mac_addr(struct rte_eth_dev *dev,
	struct rte_ether_addr *addr)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;

	PMD_INIT_FUNC_TRACE();

	if (!dpni) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -EINVAL;
	}

	ret = dpni_set_primary_mac_addr(dpni, CMD_PRI_LOW,
					priv->token, addr->addr_bytes);

	if (ret)
		DPAA2_PMD_ERR("ERR(%d) Setting the MAC ADDR failed", ret);

	return ret;
}

static int
dpaa2_dev_xstat_mac_setup_mem(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	int ret = 0;

	if (!priv->cnt_idx_dma_mem) {
		priv->cnt_idx_dma_mem = rte_zmalloc(NULL,
			DPAA2_MAC_STATS_INDEX_DMA_SIZE, RTE_CACHE_LINE_SIZE);
		if (!priv->cnt_idx_dma_mem) {
			ret = -ENOMEM;
			DPAA2_PMD_ERR("Failure to allocate memory for mac index");
			goto out;
		}

		priv->cnt_idx_iova = rte_mem_virt2iova(priv->cnt_idx_dma_mem);
		if (priv->cnt_idx_iova == RTE_BAD_IOVA) {
			ret = -ENOBUFS;
			DPAA2_PMD_ERR("%s: No IOMMU map for count index dma mem(%p)",
				__func__, priv->cnt_idx_dma_mem);
			goto err_dma_map;
		}
	}

	if (!priv->cnt_values_dma_mem) {
		priv->cnt_values_dma_mem = rte_zmalloc(NULL,
			DPAA2_MAC_STATS_VALUE_DMA_SIZE, RTE_CACHE_LINE_SIZE);
		if (!priv->cnt_values_dma_mem) {
			ret = -ENOMEM;
			DPAA2_PMD_ERR("Failure to allocate memory for mac values");
			goto err_alloc_values;
		}
		priv->cnt_values_iova = rte_mem_virt2iova(priv->cnt_values_dma_mem);
		if (priv->cnt_values_iova == RTE_BAD_IOVA) {
			ret = -ENOBUFS;
			DPAA2_PMD_ERR("%s: No IOMMU map for count values dma mem(%p)",
				__func__, priv->cnt_values_dma_mem);
			goto err_dma_map;
		}
	}

	return 0;

err_dma_map:
	rte_free(priv->cnt_values_dma_mem);
err_alloc_values:
	rte_free(priv->cnt_idx_dma_mem);
out:
	priv->cnt_idx_dma_mem = NULL;
	priv->cnt_values_dma_mem = NULL;

	return ret;
}

static int
dpaa2_dev_mac_xstats_avail(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	uint64_t rev_mac_support;

	if (priv->ep_dev_type != DPAA2_MAC)
		return false;

	rev_mac_support = RTE_FSL_MC_REV(MC_VER_MAJOR, MC_VER_MINOR, 0);
	if (priv->mc_rev >= rev_mac_support)
		return true;

	return false;
}

static int
dpaa2_dev_dpni_xstats_avail(struct rte_eth_dev *dev,
	uint8_t page_id, uint16_t param)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	uint8_t tc, i;

	if (page_id == DPNI_CGR_STATISTICS_PAGE_ID) {
		for (i = 0; i < priv->max_cgs; i++) {
			if (priv->cgid_in_use[i])
				return true;
		}
	} else if (page_id == DPNI_POLICER_STATISTICS_PAGE_ID) {
		tc = param;
		if (tc < MAX_TCS)
			return true;
	} else {
		return true;
	}

	return false;
}

static int
dpaa2_dev_xstats_get_names(struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names, uint32_t limit)
{
	uint16_t i, stat_cnt;

	stat_cnt = DPAA2_DPNI_XSTAT_MAX_NUM;
	if (dpaa2_dev_mac_xstats_avail(dev))
		stat_cnt += DPAA2_MAC_XSTAT_MAX_NUM;

	if (!limit)
		return stat_cnt;

	if (limit < stat_cnt)
		stat_cnt = limit;

	if (!xstats_names)
		return stat_cnt;

	for (i = 0; i < stat_cnt; i++)
		rte_strscpy(xstats_names[i].name, dpaa2_xstats_strings[i],
			RTE_ETH_XSTATS_NAME_SIZE);

	return stat_cnt;
}

static int
dpaa2_dev_xstats_get_by_id(struct rte_eth_dev *dev, const uint64_t *ids,
	uint64_t *values, uint32_t n)
{
	uint16_t i, id, stat_cnt, mac_num = 0;
	uint8_t page_id, stat_id;
	uint16_t param;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	bool page_fetched[DPNI_MAX_STATISTICS_PAGE_ID][DPNI_STAT_MAX_PARAM];
	/* Fetch required MAC counters in a single MC command. */
	int retcode;
	uint32_t *mac_idx;
	uint64_t *mac_val[DPAA2_MAC_XSTAT_MAX_NUM];

	retcode = dpaa2_dev_xstat_mac_setup_mem(dev);
	if (retcode) {
		DPAA2_PMD_ERR("%s: Failed(%d) to setup %s's MAC statistics!",
			__func__, retcode, dev->data->name);
		return retcode;
	}
	mac_idx = priv->cnt_idx_dma_mem;

	stat_cnt = DPAA2_DPNI_XSTAT_MAX_NUM;
	if (dpaa2_dev_mac_xstats_avail(dev))
		stat_cnt += DPAA2_MAC_XSTAT_MAX_NUM;

	memset(page_fetched, 0, sizeof(page_fetched));

	for (i = 0; i < n; i++) {
		if (ids && ids[i] >= stat_cnt) {
			DPAA2_PMD_ERR("xstats id value isn't valid");
			return -EINVAL;
		}
		id = ids ? ids[i] : i;
		if (id >= DPAA2_MAC_XSTATS_START_ID) {
			values[i] = 0;
			/* ids[] is supplied by the application and may repeat
			 * the same MAC id, so bound the collection against the
			 * mac_idx[]/mac_val[] and DMA buffer capacity.
			 */
			if (dpaa2_dev_mac_xstats_avail(dev) &&
				mac_num < DPAA2_MAC_XSTAT_MAX_NUM) {
				mac_idx[mac_num] = rte_cpu_to_le_32(id - DPAA2_MAC_XSTATS_START_ID);
				mac_val[mac_num] = &values[i];
				mac_num++;
			}
			continue;
		}
		page_id = 0;
		stat_id = 0;
		param = 0;
		retcode = dpaa2_xstats_id_parse(id, &page_id, &stat_id, &param, NULL);
		if (retcode)
			return retcode;
		if (!dpaa2_dev_dpni_xstats_avail(dev, page_id, param)) {
			values[i] = 0;
			continue;
		}
		if (page_fetched[page_id][param]) {
			values[i] = priv->pg_xstats[page_id][param].raw.counter[stat_id];
			continue;
		}
		/* Cache dpni page results: multiple xstats can share
		 * the same (page_id, param), so only fetch each pair once.
		 */
		retcode = dpni_get_statistics(dpni, CMD_PRI_LOW,
				priv->token, page_id, param,
				&priv->pg_xstats[page_id][param]);
		if (retcode) {
			DPAA2_PMD_ERR("%s: Failed(%d) to get %s's statistcis of page%d!",
				__func__, retcode, dev->data->name, page_id);
			return retcode;
		}
		page_fetched[page_id][param] = true;
		values[i] = priv->pg_xstats[page_id][param].raw.counter[stat_id];
	}

	if (mac_num > 0) {
		retcode = dpni_get_mac_statistics(dpni, CMD_PRI_LOW,
			priv->token, priv->cnt_idx_iova,
			priv->cnt_values_iova, mac_num);
		if (retcode) {
			DPAA2_PMD_ERR("%s: Failed(%d) to get %s's %d MAC statistics!",
				__func__, retcode, dev->data->name, mac_num);
			return retcode;
		}
		for (i = 0; i < mac_num; i++)
			*mac_val[i] = priv->cnt_values_dma_mem[i];
	}

	return n;
}

static int
dpaa2_dev_xstats_get_names_by_id(struct rte_eth_dev *dev,
	const uint64_t *ids, struct rte_eth_xstat_name *xstats_names,
	uint32_t limit)
{
	uint16_t i, stat_cnt;

	stat_cnt = DPAA2_DPNI_XSTAT_MAX_NUM;
	if (dpaa2_dev_mac_xstats_avail(dev))
		stat_cnt += DPAA2_MAC_XSTAT_MAX_NUM;

	if (!ids)
		return dpaa2_dev_xstats_get_names(dev, xstats_names, limit);

	for (i = 0; i < limit; i++) {
		if (ids[i] >= stat_cnt) {
			DPAA2_PMD_ERR("xstats id[%d] value(%" PRIu64 ") >= max count(%d)",
				i, ids[i], stat_cnt);
			return -EINVAL;
		}
		rte_strscpy(xstats_names[i].name,
			dpaa2_xstats_strings[ids[i]],
			RTE_ETH_XSTATS_NAME_SIZE);
	}
	return limit;
}

/*
 * dpaa2_dev_xstats_get(): Get counters of dpni and dpmac.
 * MAC (mac_*) counters are supported on MC version > 10.39.0
 * TC_x_policer_* counters are supported only when Policer is enable.
 */
static int
dpaa2_dev_xstats_get(struct rte_eth_dev *dev,
	struct rte_eth_xstat *xstats, uint32_t n)
{
	int retcode;
	uint32_t i;
	uint64_t ids[DPAA2_XSTAT_MAX_NUM], vals[DPAA2_XSTAT_MAX_NUM];

	if (!xstats || !n)
		return 0;

	if (n > DPAA2_XSTAT_MAX_NUM) {
		DPAA2_PMD_WARN("%s: Expected xstat number(%d) > max(%ld)",
			__func__, n, DPAA2_XSTAT_MAX_NUM);
		n = DPAA2_XSTAT_MAX_NUM;
	}
	for (i = 0; i < n; i++) {
		ids[i] = i;
		xstats[i].id = i;
		xstats[i].value = 0;
	}

	retcode = dpaa2_dev_xstats_get_by_id(dev, ids, vals, n);
	if (retcode < 0)
		return retcode;

	for (i = 0; i < (uint32_t)retcode; i++)
		xstats[i].value = vals[i];

	return retcode;
}

static int
dpaa2_dev_stats_get(struct rte_eth_dev *dev,
	struct rte_eth_stats *stats, struct eth_queue_stats *qstats)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	int32_t retcode;
	uint16_t i, num;
	uint64_t ids[DPAA2_STATS_XSTATS_NUM], counts[DPAA2_STATS_XSTATS_NUM] = {0};
	struct dpaa2_queue *dpaa2_q;

	PMD_INIT_FUNC_TRACE();

	rte_memcpy(ids, &dpaa2_stats_xstat_ids, sizeof(dpaa2_stats_xstat_ids));
	retcode = dpaa2_dev_xstats_get_by_id(dev, ids, counts, DPAA2_STATS_XSTATS_NUM);
	if (retcode != RTE_DIM(ids)) {
		DPAA2_PMD_ERR("%s: Failed to get xstats (%d)counters by %ld IDs",
			__func__, retcode, DPAA2_STATS_XSTATS_NUM);
		if (retcode >= 0)
			retcode = -EINVAL;
		return retcode;
	}

	rte_memcpy(stats, counts, sizeof(struct rte_eth_stats));
	stats->imissed += stats->ierrors + stats->rx_nombuf;

	if (qstats) {
		/* Fill in per queue stats */
		num = RTE_MIN(priv->nb_rx_queues, RTE_ETHDEV_QUEUE_STAT_CNTRS);
		for (i = 0; i < num; i++) {
			dpaa2_q = priv->rx_vq[i];
			qstats->q_ipackets[i] = dpaa2_q->rx_pkts;

			/* Byte counting is not implemented */
			qstats->q_ibytes[i] = 0;
		}
		num = RTE_MIN(priv->nb_tx_queues, RTE_ETHDEV_QUEUE_STAT_CNTRS);
		for (i = 0; i < num; i++) {
			dpaa2_q = priv->tx_vq[i];
			qstats->q_opackets[i] = dpaa2_q->tx_pkts;

			/* Byte counting is not implemented */
			qstats->q_obytes[i] = 0;
		}
	}

	return 0;
}

static int
dpaa2_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	int retcode;
	int i;
	struct dpaa2_queue *dpaa2_q;

	PMD_INIT_FUNC_TRACE();

	if (!dpni) {
		DPAA2_PMD_ERR("dpni is NULL");
		return -EINVAL;
	}

	retcode = dpni_reset_statistics(dpni, CMD_PRI_LOW, priv->token);
	if (retcode)
		goto error;

	/* Reset the per queue stats in dpaa2_queue structure */
	for (i = 0; i < priv->nb_rx_queues; i++) {
		dpaa2_q = priv->rx_vq[i];
		if (dpaa2_q)
			dpaa2_q->rx_pkts = 0;
	}

	for (i = 0; i < priv->nb_tx_queues; i++) {
		dpaa2_q = priv->tx_vq[i];
		if (dpaa2_q)
			dpaa2_q->tx_pkts = 0;
	}

	return 0;

error:
	DPAA2_PMD_ERR("Operation not completed:Error Code = %d", retcode);
	return retcode;
};

/* return 0 means link status changed, -1 means not changed */
static int
dpaa2_dev_link_update(struct rte_eth_dev *dev,
		      int wait_to_complete)
{
	int ret;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	struct rte_eth_link link;
	struct dpni_link_state state = {0};
	uint8_t count;

	if (!dpni) {
		DPAA2_PMD_ERR("dpni is NULL");
		return 0;
	}

	for (count = 0; count <= MAX_REPEAT_TIME; count++) {
		ret = dpni_get_link_state(dpni, CMD_PRI_LOW, priv->token,
					  &state);
		if (ret < 0) {
			DPAA2_PMD_DEBUG("error: dpni_get_link_state %d", ret);
			return ret;
		}
		if (state.up == RTE_ETH_LINK_DOWN &&
		    wait_to_complete)
			rte_delay_ms(CHECK_INTERVAL);
		else
			break;
	}

	memset(&link, 0, sizeof(struct rte_eth_link));
	link.link_status = state.up;
	link.link_speed = state.rate;

	if (state.options & DPNI_LINK_OPT_HALF_DUPLEX)
		link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
	else
		link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;

	ret = rte_eth_linkstatus_set(dev, &link);
	if (ret < 0)
		DPAA2_PMD_DEBUG("No change in status");
	else
		DPAA2_PMD_INFO("Port %d Link is %s", dev->data->port_id,
			       link.link_status ? "Up" : "Down");

	return ret;
}

/**
 * Toggle the DPNI to enable, if not already enabled.
 * This is not strictly PHY up/down - it is more of logical toggling.
 */
static int
dpaa2_dev_set_link_up(struct rte_eth_dev *dev)
{
	int ret = -EINVAL;
	struct dpaa2_dev_priv *priv;
	struct fsl_mc_io *dpni;
	int en = 0;
	struct dpni_link_state state = {0};

	priv = dev->data->dev_private;
	dpni = dev->process_private;

	if (!dpni) {
		DPAA2_PMD_ERR("dpni is NULL");
		return ret;
	}

	/* Check if DPNI is currently enabled */
	ret = dpni_is_enabled(dpni, CMD_PRI_LOW, priv->token, &en);
	if (ret) {
		/* Unable to obtain dpni status; Not continuing */
		DPAA2_PMD_ERR("Interface Link UP failed (%d)", ret);
		return ret;
	}

	/* Enable link if not already enabled */
	if (!en) {
		ret = dpni_enable(dpni, CMD_PRI_LOW, priv->token);
		if (ret) {
			DPAA2_PMD_ERR("Interface Link UP failed (%d)", ret);
			return ret;
		}
	}
	ret = dpni_get_link_state(dpni, CMD_PRI_LOW, priv->token, &state);
	if (ret < 0) {
		DPAA2_PMD_DEBUG("Unable to get link state (%d)", ret);
		return ret;
	}

	/* changing tx burst function to start enqueues */
	dev->tx_pkt_burst = dpaa2_dev_tx;
	dev->data->dev_link.link_status = state.up;
	dev->data->dev_link.link_speed = state.rate;

	if (state.options & DPNI_LINK_OPT_HALF_DUPLEX)
		dev->data->dev_link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
	else
		dev->data->dev_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;

	if (state.up)
		DPAA2_PMD_DEBUG("Port %d Link is Up", dev->data->port_id);
	else
		DPAA2_PMD_DEBUG("Port %d Link is Down", dev->data->port_id);
	return ret;
}

/**
 * Toggle the DPNI to disable, if not already disabled.
 * This is not strictly PHY up/down - it is more of logical toggling.
 */
static int
dpaa2_dev_set_link_down(struct rte_eth_dev *dev)
{
	int ret = -EINVAL;
	struct dpaa2_dev_priv *priv;
	struct fsl_mc_io *dpni;
	int dpni_enabled = 0;
	int retries = 10;

	PMD_INIT_FUNC_TRACE();

	priv = dev->data->dev_private;
	dpni = dev->process_private;

	if (!dpni) {
		DPAA2_PMD_ERR("Device has not yet been configured");
		return ret;
	}

	/*changing  tx burst function to avoid any more enqueues */
	dev->tx_pkt_burst = rte_eth_pkt_burst_dummy;

	/* Loop while dpni_disable() attempts to drain the egress FQs
	 * and confirm them back to us.
	 */
	do {
		ret = dpni_disable(dpni, 0, priv->token);
		if (ret) {
			DPAA2_PMD_ERR("dpni disable failed (%d)", ret);
			return ret;
		}
		ret = dpni_is_enabled(dpni, 0, priv->token, &dpni_enabled);
		if (ret) {
			DPAA2_PMD_ERR("dpni enable check failed (%d)", ret);
			return ret;
		}
		if (dpni_enabled)
			/* Allow the MC some slack */
			rte_delay_ms(CHECK_INTERVAL);
	} while (dpni_enabled && --retries);

	if (!retries) {
		DPAA2_PMD_WARN("Retry count exceeded disabling dpni");
		/* todo- we may have to manually cleanup queues.
		 */
	} else {
		DPAA2_PMD_INFO("Port %d Link DOWN successful",
			       dev->data->port_id);
	}

	dev->data->dev_link.link_status = 0;

	return ret;
}

static int
dpaa2_flow_ctrl_get(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	int ret = -EINVAL;
	struct dpaa2_dev_priv *priv;
	struct fsl_mc_io *dpni;
	struct dpni_link_cfg cfg = {0};

	PMD_INIT_FUNC_TRACE();

	priv = dev->data->dev_private;
	dpni = dev->process_private;

	if (!dpni || !fc_conf) {
		DPAA2_PMD_ERR("device not configured");
		return ret;
	}

	ret = dpni_get_link_cfg(dpni, CMD_PRI_LOW, priv->token, &cfg);
	if (ret) {
		DPAA2_PMD_ERR("error: dpni_get_link_cfg %d", ret);
		return ret;
	}

	memset(fc_conf, 0, sizeof(struct rte_eth_fc_conf));
	if (cfg.options & DPNI_LINK_OPT_PAUSE) {
		/* DPNI_LINK_OPT_PAUSE set
		 *  if ASYM_PAUSE not set,
		 *	RX Side flow control (handle received Pause frame)
		 *	TX side flow control (send Pause frame)
		 *  if ASYM_PAUSE set,
		 *	RX Side flow control (handle received Pause frame)
		 *	No TX side flow control (send Pause frame disabled)
		 */
		if (!(cfg.options & DPNI_LINK_OPT_ASYM_PAUSE))
			fc_conf->mode = RTE_ETH_FC_FULL;
		else
			fc_conf->mode = RTE_ETH_FC_RX_PAUSE;
	} else {
		/* DPNI_LINK_OPT_PAUSE not set
		 *  if ASYM_PAUSE set,
		 *	TX side flow control (send Pause frame)
		 *	No RX side flow control (No action on pause frame rx)
		 *  if ASYM_PAUSE not set,
		 *	Flow control disabled
		 */
		if (cfg.options & DPNI_LINK_OPT_ASYM_PAUSE)
			fc_conf->mode = RTE_ETH_FC_TX_PAUSE;
		else
			fc_conf->mode = RTE_ETH_FC_NONE;
	}

	return ret;
}

static int
dpaa2_flow_ctrl_set(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	int ret = -EINVAL;
	struct dpaa2_dev_priv *priv;
	struct fsl_mc_io *dpni;
	struct dpni_link_cfg cfg = {0};

	PMD_INIT_FUNC_TRACE();

	priv = dev->data->dev_private;
	dpni = dev->process_private;

	if (!dpni) {
		DPAA2_PMD_ERR("dpni is NULL");
		return ret;
	}

	/* It is necessary to obtain the current cfg before setting fc_conf
	 * as MC would return error in case rate, autoneg or duplex values are
	 * different.
	 */
	ret = dpni_get_link_cfg(dpni, CMD_PRI_LOW, priv->token, &cfg);
	if (ret) {
		DPAA2_PMD_ERR("Unable to get link cfg (err=%d)", ret);
		return ret;
	}

	/* Disable link before setting configuration */
	dpaa2_dev_set_link_down(dev);

	/* update cfg with fc_conf */
	switch (fc_conf->mode) {
	case RTE_ETH_FC_FULL:
		/* Full flow control;
		 * OPT_PAUSE set, ASYM_PAUSE not set
		 */
		cfg.options |= DPNI_LINK_OPT_PAUSE;
		cfg.options &= ~DPNI_LINK_OPT_ASYM_PAUSE;
		break;
	case RTE_ETH_FC_TX_PAUSE:
		/* Enable RX flow control
		 * OPT_PAUSE not set;
		 * ASYM_PAUSE set;
		 */
		cfg.options |= DPNI_LINK_OPT_ASYM_PAUSE;
		cfg.options &= ~DPNI_LINK_OPT_PAUSE;
		break;
	case RTE_ETH_FC_RX_PAUSE:
		/* Enable TX Flow control
		 * OPT_PAUSE set
		 * ASYM_PAUSE set
		 */
		cfg.options |= DPNI_LINK_OPT_PAUSE;
		cfg.options |= DPNI_LINK_OPT_ASYM_PAUSE;
		break;
	case RTE_ETH_FC_NONE:
		/* Disable Flow control
		 * OPT_PAUSE not set
		 * ASYM_PAUSE not set
		 */
		cfg.options &= ~DPNI_LINK_OPT_PAUSE;
		cfg.options &= ~DPNI_LINK_OPT_ASYM_PAUSE;
		break;
	default:
		DPAA2_PMD_ERR("Incorrect Flow control flag (%d)",
			      fc_conf->mode);
		return -EINVAL;
	}

	ret = dpni_set_link_cfg(dpni, CMD_PRI_LOW, priv->token, &cfg);
	if (ret)
		DPAA2_PMD_ERR("Unable to set Link configuration (err=%d)",
			      ret);

	/* Enable link */
	dpaa2_dev_set_link_up(dev);

	return ret;
}

static int
dpaa2_dev_rss_hash_update(struct rte_eth_dev *dev,
			  struct rte_eth_rss_conf *rss_conf)
{
	struct rte_eth_dev_data *data = dev->data;
	struct dpaa2_dev_priv *priv = data->dev_private;
	struct rte_eth_conf *eth_conf = &data->dev_conf;
	int ret, tc_index;

	PMD_INIT_FUNC_TRACE();

	if (rss_conf->rss_hf) {
		for (tc_index = 0; tc_index < priv->num_rx_tc; tc_index++) {
			ret = dpaa2_update_flow_rss_dist(dev, rss_conf->rss_hf,
				tc_index);
			if (ret)
				break;
		}
	} else {
		for (tc_index = 0; tc_index < priv->num_rx_tc; tc_index++) {
			ret = dpaa2_remove_flow_rss_dist(dev, tc_index);
			if (ret)
				break;
		}
	}
	if (ret) {
		DPAA2_PMD_ERR("%s: %s flow dist on tc%d err(%d)",
			data->name, rss_conf->rss_hf ? "set" : "remove",
			tc_index, ret);

		return ret;
	}
	eth_conf->rx_adv_conf.rss_conf.rss_hf = rss_conf->rss_hf;
	return 0;
}

static int
dpaa2_dev_rss_hash_conf_get(struct rte_eth_dev *dev,
			    struct rte_eth_rss_conf *rss_conf)
{
	struct rte_eth_dev_data *data = dev->data;
	struct rte_eth_conf *eth_conf = &data->dev_conf;

	/* dpaa2 does not support rss_key, so length should be 0*/
	rss_conf->rss_key_len = 0;
	rss_conf->rss_hf = eth_conf->rx_adv_conf.rss_conf.rss_hf;
	return 0;
}

/* Emulation of the standard DPDK RETA API on top of DPAA2's
 * dpni_set_rx_hash_dist MC command.
 *
 * DPAA2 hardware dispatches incoming frames using 'queue_id = hash % dist_size'
 * (no software-visible indirection table). To expose the standard
 * rte_eth_dev_rss_reta_update() interface, we accept ONLY uniform patterns of
 * the form 'reta[i] = i % N' where N is in the HW-allowed dist_size list. Any
 * other pattern (weighted RSS, non-contiguous queue IDs, gaps) is rejected
 * with -ENOTSUP. This is enough to support dynamic RSS scale-up/down across
 * a contiguous queue subset, which is the main use case for adaptive
 * dataplane CPU usage.
 *
 * Applies the new dist_size on every configured RX TC, mirroring the
 * behavior of dpaa2_dev_rss_hash_update().
 */
static int
dpaa2_dev_rss_reta_update(struct rte_eth_dev *dev,
			  struct rte_eth_rss_reta_entry64 *reta_conf,
			  uint16_t reta_size)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct rte_eth_conf *eth_conf = &dev->data->dev_conf;
	uint16_t i, max_q = 0, n;
	int tc_index, ret;
	bool any_set = false;

	PMD_INIT_FUNC_TRACE();

	if (reta_size != DPAA2_RETA_SIZE) {
		DPAA2_PMD_ERR("Invalid reta_size %u (expected %u)",
			      reta_size, DPAA2_RETA_SIZE);
		return -EINVAL;
	}

	/* dpaa2 cannot merge a partial RETA into the live table, so only a
	 * full update (every entry of every group) is accepted.
	 */
	for (i = 0; i < reta_size / RTE_ETH_RETA_GROUP_SIZE; i++) {
		if (reta_conf[i].mask != UINT64_MAX) {
			DPAA2_PMD_ERR("partial RETA update not supported; set all %u entries",
				      DPAA2_RETA_SIZE);
			return -ENOTSUP;
		}
	}

	/* First pass: validate queue IDs, find max, and require at least
	 * one slot to be selected via the per-group mask.
	 */
	for (i = 0; i < reta_size; i++) {
		uint16_t grp = i / RTE_ETH_RETA_GROUP_SIZE;
		uint16_t pos = i % RTE_ETH_RETA_GROUP_SIZE;
		uint16_t q;

		if (!(reta_conf[grp].mask & (1ULL << pos)))
			continue;
		any_set = true;

		q = reta_conf[grp].reta[pos];
		if (q >= dev->data->nb_rx_queues) {
			DPAA2_PMD_ERR("reta[%u] = %u out of range (max %u)",
				i, q, dev->data->nb_rx_queues - 1);
			return -EINVAL;
		}
		if (q > max_q)
			max_q = q;
	}

	if (!any_set) {
		DPAA2_PMD_WARN("reta_update called with empty mask, no-op");
		return 0;
	}

	n = max_q + 1;

	/* Second pass: enforce the uniform pattern reta[i] = i % n on every
	 * slot the user has selected. dpaa2 HW cannot honor any other layout.
	 */
	for (i = 0; i < reta_size; i++) {
		uint16_t grp = i / RTE_ETH_RETA_GROUP_SIZE;
		uint16_t pos = i % RTE_ETH_RETA_GROUP_SIZE;
		uint16_t expected = i % n;
		uint16_t q;

		if (!(reta_conf[grp].mask & (1ULL << pos)))
			continue;

		q = reta_conf[grp].reta[pos];
		if (q != expected) {
			DPAA2_PMD_ERR("Non-uniform RETA pattern at slot %u "
				"(got queue %u, expected %u). dpaa2 HW "
				"only supports queue_id = hash mod N with "
				"contiguous queues 0..N-1.",
				i, q, expected);
			return -ENOTSUP;
		}
	}

	/* The requested distribution size cannot exceed the number of
	 * distribution queues provisioned per TC. Any HW-specific limitation
	 * on the exact value is enforced later by the rte_flow update.
	 */
	if (n > priv->dist_queues) {
		DPAA2_PMD_ERR("dist_size %u exceeds max distribution queues %u",
			n, priv->dist_queues);
		return -ENOTSUP;
	}

	/* Apply on every configured RX TC, matching rss_hash_update behavior.
	 * Program the new dist_size into each TC's RSS flow profile and push
	 * it to the live flow via rte_flow_actions_update().
	 */
	for (tc_index = 0; tc_index < priv->num_rx_tc; tc_index++) {
		struct dpaa2_flow_tbl_profile *tbl_profile =
			&priv->flow_profile.tc_profile[tc_index];

		tbl_profile->tc_cfg.dist_size = n;
		ret = dpaa2_update_flow_rss_dist(dev,
				eth_conf->rx_adv_conf.rss_conf.rss_hf,
				tc_index);
		if (ret) {
			DPAA2_PMD_ERR("Failed to apply dist_size=%u on tc%d (err=%d)",
				n, tc_index, ret);
			return ret;
		}
		priv->dist_size_cur[tc_index] = n;
	}

	DPAA2_PMD_DEBUG("RETA updated: dist_size now %u on %u TC(s)",
			n, priv->num_rx_tc);
	return 0;
}

/* Synthesizes a RETA snapshot from the currently-active dist_size on TC 0.
 * Since DPAA2 always uses uniform 'hash mod N' distribution, the returned
 * RETA is reta[i] = i % dist_size_cur[0].
 */
static int
dpaa2_dev_rss_reta_query(struct rte_eth_dev *dev,
			 struct rte_eth_rss_reta_entry64 *reta_conf,
			 uint16_t reta_size)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	uint16_t i, n;

	PMD_INIT_FUNC_TRACE();

	if (reta_size != DPAA2_RETA_SIZE) {
		DPAA2_PMD_ERR("Invalid reta_size %u (expected %u)",
			      reta_size, DPAA2_RETA_SIZE);
		return -EINVAL;
	}

	/* Use the cached dist_size on TC 0 (representative). Fall back to the
	 * default (nb_rx_queues clamped to dist_queues) when never programmed.
	 */
	n = priv->dist_size_cur[0];
	if (n == 0) {
		n = priv->dist_queues;
		if (n > dev->data->nb_rx_queues)
			n = dev->data->nb_rx_queues;
	}
	if (n == 0)
		return -EINVAL;

	for (i = 0; i < reta_size; i++) {
		uint16_t grp = i / RTE_ETH_RETA_GROUP_SIZE;
		uint16_t pos = i % RTE_ETH_RETA_GROUP_SIZE;

		if (reta_conf[grp].mask & (1ULL << pos))
			reta_conf[grp].reta[pos] = i % n;
	}

	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(dpaa2_eth_eventq_attach)
int dpaa2_eth_eventq_attach(const struct rte_eth_dev *dev,
		int eth_rx_queue_id,
		struct dpaa2_dpcon_dev *dpcon,
		const struct rte_event_eth_rx_adapter_queue_conf *queue_conf)
{
	struct dpaa2_dev_priv *eth_priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;
	struct dpaa2_queue *dpaa2_ethq = eth_priv->rx_vq[eth_rx_queue_id];
	uint8_t flow_id;
	struct dpni_queue *cfg;
	uint8_t options, priority;
	int ret;

	flow_id = dpaa2_ethq->flow_id;
	cfg = dpaa2_ethq->cfg;

	if (queue_conf->ev.sched_type == RTE_SCHED_TYPE_PARALLEL)
		dpaa2_ethq->cb = dpaa2_dev_process_parallel_event;
	else if (queue_conf->ev.sched_type == RTE_SCHED_TYPE_ATOMIC)
		dpaa2_ethq->cb = dpaa2_dev_process_atomic_event;
	else if (queue_conf->ev.sched_type == RTE_SCHED_TYPE_ORDERED)
		dpaa2_ethq->cb = dpaa2_dev_process_ordered_event;
	else
		return -EINVAL;

	priority = (RTE_EVENT_DEV_PRIORITY_LOWEST / queue_conf->ev.priority) *
		   (dpcon->num_priorities - 1);

	if (!cfg) {
		DPAA2_PMD_ERR("%s: %s-rxq%d was not setup yet!",
			__func__, dev->data->name, eth_rx_queue_id);
		return -EINVAL;
	}
	options = DPNI_QUEUE_OPT_DEST;
	cfg->destination.type = DPNI_DEST_DPCON;
	cfg->destination.id = dpcon->dpcon_id;
	cfg->destination.priority = priority;

	if (queue_conf->ev.sched_type == RTE_SCHED_TYPE_ATOMIC) {
		options |= DPNI_QUEUE_OPT_HOLD_ACTIVE;
		cfg->destination.hold_active = 1;
	}

	if (queue_conf->ev.sched_type == RTE_SCHED_TYPE_ORDERED &&
			!eth_priv->en_ordered) {
		struct opr_cfg ocfg;

		/* Restoration window size = 256 frames */
		ocfg.oprrws = 3;
		/* Restoration window size = 512 frames for LX2 */
		if (dpaa2_svr_family == SVR_LX2160A)
			ocfg.oprrws = 4;
		/* Auto advance NESN window enabled */
		ocfg.oa = 1;
		/* Late arrival window size disabled */
		ocfg.olws = 0;
		/* ORL resource exhaustion advance NESN disabled */
		ocfg.oeane = 0;
		/* Loose ordering enabled */
		ocfg.oloe = 1;
		eth_priv->en_loose_ordered = 1;
		/* Strict ordering enabled if explicitly set */
		if (getenv("DPAA2_STRICT_ORDERING_ENABLE")) {
			ocfg.oloe = 0;
			eth_priv->en_loose_ordered = 0;
		}

		ret = dpni_set_opr(dpni, CMD_PRI_LOW, eth_priv->token,
				   dpaa2_ethq->tc_index, flow_id,
				   OPR_OPT_CREATE, &ocfg, 0);
		if (ret) {
			DPAA2_PMD_ERR("Error setting opr: ret: %d", ret);
			return ret;
		}

		eth_priv->en_ordered = 1;
	}

	options |= DPNI_QUEUE_OPT_USER_CTX;
	cfg->user_context = (size_t)(dpaa2_ethq);

	ret = dpni_set_queue(dpni, CMD_PRI_LOW, eth_priv->token, DPNI_QUEUE_RX,
			     dpaa2_ethq->tc_index, flow_id, options, cfg);
	if (ret) {
		DPAA2_PMD_ERR("Error in dpni_set_queue: ret: %d", ret);
		return ret;
	}

	rte_memcpy(&dpaa2_ethq->ev, &queue_conf->ev, sizeof(struct rte_event));

	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(dpaa2_eth_eventq_detach)
int dpaa2_eth_eventq_detach(const struct rte_eth_dev *dev,
		int eth_rx_queue_id)
{
	struct dpaa2_dev_priv *eth_priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev->process_private;
	struct dpaa2_queue *dpaa2_ethq = eth_priv->rx_vq[eth_rx_queue_id];
	struct dpni_queue *cfg;
	int ret;

	cfg = dpaa2_ethq->cfg;
	cfg->destination.type = DPNI_DEST_NONE;
	dpaa2_ethq->options &= ~DPNI_QUEUE_OPT_DEST;

	ret = dpni_set_queue(dpni, CMD_PRI_LOW, eth_priv->token, DPNI_QUEUE_RX,
		dpaa2_ethq->tc_index, dpaa2_ethq->flow_id, dpaa2_ethq->options, cfg);
	if (ret)
		DPAA2_PMD_ERR("Error in dpni_set_queue: ret: %d", ret);

	return ret;
}

static int
dpaa2_dev_flow_ops_get(struct rte_eth_dev *dev,
		       const struct rte_flow_ops **ops)
{
	if (!dev)
		return -ENODEV;

	*ops = &dpaa2_flow_ops;
	return 0;
}

static void
dpaa2_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_rxq_info *qinfo)
{
	struct dpaa2_queue *rxq;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = dev->process_private;
	uint16_t max_frame_length;

	rxq = dev->data->rx_queues[queue_id];

	qinfo->mp = rxq->mb_pool;
	qinfo->scattered_rx = dev->data->scattered_rx;
	qinfo->nb_desc = rxq->nb_desc;
	if (dpni_get_max_frame_length(dpni, CMD_PRI_LOW, priv->token,
				&max_frame_length) == 0)
		qinfo->rx_buf_size = max_frame_length;

	qinfo->conf.rx_free_thresh = 1;
	qinfo->conf.rx_drop_en = 1;
	qinfo->conf.rx_deferred_start = 0;
	qinfo->conf.offloads = rxq->offloads;
}

static void
dpaa2_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_txq_info *qinfo)
{
	struct dpaa2_queue *txq;

	txq = dev->data->tx_queues[queue_id];

	qinfo->nb_desc = txq->nb_desc;
	qinfo->conf.tx_thresh.pthresh = 0;
	qinfo->conf.tx_thresh.hthresh = 0;
	qinfo->conf.tx_thresh.wthresh = 0;

	qinfo->conf.tx_free_thresh = 0;
	qinfo->conf.tx_rs_thresh = 0;
	qinfo->conf.offloads = txq->offloads;
	qinfo->conf.tx_deferred_start = 0;
}

static int
dpaa2_tm_ops_get(struct rte_eth_dev *dev __rte_unused, void *ops)
{
	*(const void **)ops = &dpaa2_tm_ops;

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_dpaa2_thread_init, 21.08)
void
rte_pmd_dpaa2_thread_init(void)
{
	int ret;

	if (unlikely(!DPAA2_PER_LCORE_DPIO)) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			DPAA2_PMD_ERR(
				"Failed to allocate IO portal, tid: %d",
				rte_gettid());
			return;
		}
	}
}

/* Arm rx-queue interrupts on the worker lcore: subscribe its ethrx portal to
 * the queue's DPCON channel (one-shot per-portal MC) and unmask the portal DQRI
 * (pure QBMan).
 *
 * Affinity is static queue-to-lcore; a lcore may own several rx queues. The
 * DQRI and the eventfd are portal-wide; on wake the worker polls each armed
 * queue's channel (one FQ per channel, no per-frame demux) and the portal's
 * inhibit bit is reference-counted by the number of its
 * queues currently armed (ethrx_intr_refcnt) -- disabling one queue must not
 * mask wakeups still wanted by its siblings. napi_armed and ethrx_intr_refcnt
 * are plain (not atomic): these ops run on the queue's owner lcore against its
 * own portal (one portal per lcore), so per-portal isolation keeps them from
 * racing, not control-plane serialization.
 *
 * A re-home reclaims the channel by poking the old portal, so the caller must
 * have quiesced the previous owner and disabled the queue there; napi_armed is
 * then 0 and only the new portal is counted.
 */
/* Drain the portal DQRR (consuming pending CDANs) then clear SWPn_ISR.
 * Clearing while the ring is non-empty re-asserts the DQRI at once, so drain
 * first. Shared by arm and disarm; the caller sets the inhibit bit.
 */
static void
dpaa2_napi_drain_portal(struct dpaa2_dpio_dev *dpio)
{
	const struct qbman_result *dq;

	while ((dq = qbman_swp_dqrr_next(dpio->sw_portal)))
		qbman_swp_dqrr_consume(dpio->sw_portal, dq);
	/* flush the indices still pending in the DQRR consume vector */
	qbman_swp_dqrr_consume(dpio->sw_portal, NULL);
	qbman_swp_interrupt_clear_status(dpio->sw_portal, 0xffffffff);
}

/* Quiesce this queue's in-flight prefetch VDQ before a sleep: a pull left in
 * flight strands the FQ (no empty->non-empty edge, no CDAN). Returns -EAGAIN if
 * the completed pull captured a frame -> abort the sleep and keep polling.
 */
static int
dpaa2_napi_quiesce_vdq(struct dpaa2_queue *dpaa2_q)
{
	struct queue_storage_info_t *qs = dpaa2_q->q_storage[rte_lcore_id()];
	struct qbman_result *dq;

	if (!qs || !qs->active_dqs)
		return 0;
	dq = qs->active_dqs;
	while (!qbman_check_command_complete(dq))
		;
	/* a completed pull holding a frame must not be dropped: leave it. Inspect
	 * without qbman_check_new_result(), which zeroes the token the next burst
	 * needs to detect completion.
	 */
	if (!qbman_result_DQ_is_pull_complete(dq) ||
	    (qbman_result_DQ_flags(dq) & QBMAN_DQ_STAT_VALIDFRAME)) {
		return -EAGAIN;
	}
	/* empty pull-complete: consume the token, drop the storage for a fresh pull */
	while (!qbman_check_new_result(dq))
		;
	clear_swp_active_dqs(qs->active_dpio_id);
	qs->active_dqs = NULL;
	return 0;
}

/* Route this DPCON's CDAN to the worker's DPIO at MC level (re-issued on
 * re-home), with the queue as the wake-demux context.
 */
static int
dpaa2_napi_set_cdan_dest(struct dpaa2_queue *dpaa2_q, struct dpaa2_dpio_dev *dpio)
{
	struct dpcon_notification_cfg ncfg = {
		.dpio_id = dpio->hw_id,
		.priority = 0,
		.user_ctx = (uint64_t)(uintptr_t)dpaa2_q,
	};

	return dpcon_set_notification(&dpaa2_q->napi_dpcon->dpcon,
			CMD_PRI_LOW, dpaa2_q->napi_dpcon->token, &ncfg);
}

/* (Re)subscribe the queue's DPCON channel to dpio: set the CDAN context on the
 * new portal, route notifications there, and wire the queue's eventfd into the
 * generic rx-intr epoll. CDAN is not enabled here; the arm path is the sole
 * arming point. Runs on the initial arm and on an lcore re-home.
 */
static int
dpaa2_napi_subscribe(struct rte_eth_dev *dev, uint16_t queue_id,
		     struct dpaa2_dpio_dev *dpio, struct dpaa2_dpio_dev *old)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_queue *dpaa2_q = priv->rx_vq[queue_id];
	uint16_t chid = dpaa2_q->napi_dpcon->qbman_ch_id;
	int ret;

	if (old) {
		/* re-home: CDAN already off old (-EBUSY ensures it was disabled
		 * first); just drop the sub, never touch a foreign portal.
		 */
		rte_atomic_store_explicit(&dpaa2_q->napi_sub_dpio, NULL,
				rte_memory_order_release);
	}
	/* push_set ORs the channel-0 bit (idempotent across queues sharing the
	 * portal); CDAN context = the queue, so the wake path can demux it.
	 */
	qbman_swp_push_set(dpio->sw_portal, 0, 1);
	/* context only; the arm path is the sole place that enables the CDAN */
	ret = qbman_swp_CDAN_set_context(dpio->sw_portal, chid,
			(uint64_t)(uintptr_t)dpaa2_q);
	if (ret) {
		DPAA2_PMD_ERR("napi: CDAN set_context rxq %d: %d", queue_id, ret);
		return ret;
	}
	ret = dpaa2_napi_set_cdan_dest(dpaa2_q, dpio);
	if (ret) {
		DPAA2_PMD_ERR("napi: dpcon_set_notification rxq %d: %d",
			      queue_id, ret);
		return ret;		/* CDAN not enabled here -> nothing to unwind */
	}
	DPAA2_PMD_DEBUG("napi-cdan rxq=%u dpio=%u chid=%u",
		queue_id, dpio->index, chid);
	/* point the queue's eventfd at the portal DQRI fd for the generic epoll */
	if (rte_intr_vec_list_index_set(dev->intr_handle, queue_id,
			queue_id + RTE_INTR_VEC_RXTX_OFFSET) ||
	    rte_intr_efds_index_set(dev->intr_handle, queue_id,
			rte_intr_fd_get(dpio->intr_handle))) {
		DPAA2_PMD_ERR("napi: efd wiring rxq %d", queue_id);
		return -EIO;
	}
	rte_atomic_store_explicit(&dpaa2_q->napi_sub_dpio, dpio,
			rte_memory_order_release);
	/* pin this portal's MSI to the worker's core: a CDAN wake then lands on
	 * the same core the worker sleeps on, instead of the default spread.
	 */
	dpaa2_dpio_affine_intr_to_core(dpio->hw_id);
	return 0;
}

static int
dpaa2_dev_rx_queue_intr_enable(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_queue *dpaa2_q = priv->rx_vq[queue_id];
	struct dpaa2_dpio_dev *dpio, *old;
	int ret;

	/* the generic API has no dev_started guard (unlike the burst dummy ops),
	 * so it can reach us after a stop; do not arm a stopped port, let the
	 * caller fall back to polling.
	 */
	if (!dev->data->dev_started)
		return -EIO;
	if (!dpaa2_q->napi_dpcon)
		return -ENOTSUP;	/* no channel -> caller keeps polling */

	if (dpaa2_affine_qbman_ethrx_swp())
		return -EIO;
	dpio = DPAA2_PER_LCORE_ETHRX_DPIO;

	old = rte_atomic_load_explicit(&dpaa2_q->napi_sub_dpio, rte_memory_order_acquire);
	if (old && old != dpio && dpaa2_q->napi_armed) {
		DPAA2_PMD_ERR("rxq %d still armed on another portal; disable it first",
			      queue_id);
		return -EBUSY;
	}

	ret = dpaa2_napi_quiesce_vdq(dpaa2_q);
	if (ret)
		return ret;

	/* holdoff 0: the DQRI fires immediately on the first entry, so the
	 * threshold is moot (1 here). build_epoll=false: the generic rx-intr API
	 * waits on the application epoll, not the portal's private one. Idempotent
	 * per dpio.
	 */
	ret = dpaa2_dpio_intr_init(dpio, 1, 0, false);
	if (ret)
		return ret;

	if (old != dpio) {
		ret = dpaa2_napi_subscribe(dev, queue_id, dpio, old);
		if (ret)
			return ret;
	}

	/* first arm on this portal: mask + drain stale CDANs, so the unmask on
	 * the 0 -> 1 edge below is the sole DQRI open (independent of prior state)
	 */
	if (!dpaa2_q->napi_armed && dpio->ethrx_intr_refcnt == 0) {
		qbman_swp_interrupt_set_inhibit(dpio->sw_portal, 1);
		dpaa2_napi_drain_portal(dpio);
	}

	/* CDAN is one-shot and the sole arming point, re-armed every sleep.
	 * Publish armed/refcnt only on a successful initial enable.
	 */
	ret = qbman_swp_CDAN_enable(dpio->sw_portal, dpaa2_q->napi_dpcon->qbman_ch_id);
	if (ret) {
		DPAA2_PMD_DEBUG("napi: CDAN arm rxq %d: %d", queue_id, ret);
		/* initial arm: nothing published; re-arm: state kept. Don't sleep. */
		return -EAGAIN;
	}

	if (!dpaa2_q->napi_armed) {
		dpaa2_q->napi_armed = 1;
		/* unmask the portal DQRI once, on the 0 -> 1 armed-queue edge */
		if (dpio->ethrx_intr_refcnt++ == 0)
			qbman_swp_interrupt_set_inhibit(dpio->sw_portal, 0);
	}

	return 0;
}

/* Disarm rx-queue interrupts for this queue. The portal DQRI is masked only
 * once the last of its queues disarms; act on the portal the queue is actually
 * subscribed to, not the caller's current portal.
 */
static int
dpaa2_dev_rx_queue_intr_disable(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_queue *dpaa2_q = priv->rx_vq[queue_id];
	struct dpaa2_dpio_dev *dpio;
	uint64_t ev;
	ssize_t nb;

	dpio = rte_atomic_load_explicit(&dpaa2_q->napi_sub_dpio, rte_memory_order_acquire);
	if (dpio && dpaa2_q->napi_armed) {
		dpaa2_q->napi_armed = 0;
		/* Silence this queue's CDAN on the portal the worker owns. Runs on
		 * the polling lcore, so this is the only safe place to drive the
		 * single-owner software portal. It also returns the channel to the
		 * pool clean (CDAN disabled) and lets a sibling queue keep its own
		 * interrupt (per-queue, unlike the portal-wide DQRI mask below).
		 */
		qbman_swp_CDAN_disable(dpio->sw_portal,
				dpaa2_q->napi_dpcon->qbman_ch_id);
		if (dpio->ethrx_intr_refcnt > 0 &&
		    --dpio->ethrx_intr_refcnt == 0) {
			/* last queue on the shared portal: drain + clear so the next
			 * arm sees a clean portal (once per wake), then mask.
			 */
			dpaa2_napi_drain_portal(dpio);
			qbman_swp_interrupt_set_inhibit(dpio->sw_portal, 1);
			/* drain the VFIO eventfd: it is EPOLLET and the EAL leaves
			 * RTE_INTR_HANDLE_EXT undrained, so a stale count suppresses the
			 * next wake edge. Same as dpaa/mlx4/mlx5 do on disarm.
			 */
			nb = read(rte_intr_fd_get(dpio->intr_handle), &ev, sizeof(ev));
			if (nb != (ssize_t)sizeof(ev) && errno != EAGAIN)
				DPAA2_PMD_DEBUG("napi: eventfd drain rxq %d (%zd)",
						queue_id, nb);
		}
	}

	return 0;
}

static struct eth_dev_ops dpaa2_ethdev_ops = {
	.dev_configure	  = dpaa2_eth_dev_configure,
	.dev_start	      = dpaa2_dev_start,
	.dev_stop	      = dpaa2_dev_stop,
	.dev_close	      = dpaa2_dev_close,
	.promiscuous_enable   = dpaa2_dev_promiscuous_enable,
	.promiscuous_disable  = dpaa2_dev_promiscuous_disable,
	.allmulticast_enable  = dpaa2_dev_allmulticast_enable,
	.allmulticast_disable = dpaa2_dev_allmulticast_disable,
	.dev_set_link_up      = dpaa2_dev_set_link_up,
	.dev_set_link_down    = dpaa2_dev_set_link_down,
	.link_update	   = dpaa2_dev_link_update,
	.stats_get	       = dpaa2_dev_stats_get,
	.xstats_get	       = dpaa2_dev_xstats_get,
	.xstats_get_by_id     = dpaa2_dev_xstats_get_by_id,
	.xstats_get_names_by_id = dpaa2_dev_xstats_get_names_by_id,
	.xstats_get_names      = dpaa2_dev_xstats_get_names,
	.stats_reset	   = dpaa2_dev_stats_reset,
	.xstats_reset	      = dpaa2_dev_stats_reset,
	.fw_version_get	   = dpaa2_fw_version_get,
	.dev_infos_get	   = dpaa2_dev_info_get,
	.dev_supported_ptypes_get = dpaa2_supported_ptypes_get,
	.mtu_set           = dpaa2_dev_mtu_set,
	.vlan_filter_set      = dpaa2_vlan_filter_set,
	.vlan_offload_set     = dpaa2_vlan_offload_set,
	.vlan_tpid_set	      = dpaa2_vlan_tpid_set,
	.rx_queue_setup    = dpaa2_dev_rx_queue_setup,
	.rx_queue_release  = dpaa2_dev_rx_queue_release,
	/* arm/disarm drive the per-lcore QBMan portal: the app must call
	 * rte_eth_dev_rx_intr_disable() from the polling lcore before stop/close.
	 */
	.rx_queue_intr_enable = dpaa2_dev_rx_queue_intr_enable,
	.rx_queue_intr_disable = dpaa2_dev_rx_queue_intr_disable,
	.tx_queue_setup    = dpaa2_dev_tx_queue_setup,
	.rx_burst_mode_get = dpaa2_dev_rx_burst_mode_get,
	.tx_burst_mode_get = dpaa2_dev_tx_burst_mode_get,
	.flow_ctrl_get	      = dpaa2_flow_ctrl_get,
	.flow_ctrl_set	      = dpaa2_flow_ctrl_set,
	.mac_addr_add         = dpaa2_dev_add_mac_addr,
	.mac_addr_remove      = dpaa2_dev_remove_mac_addr,
	.mac_addr_set         = dpaa2_dev_set_mac_addr,
	.rss_hash_update      = dpaa2_dev_rss_hash_update,
	.rss_hash_conf_get    = dpaa2_dev_rss_hash_conf_get,
	.reta_update          = dpaa2_dev_rss_reta_update,
	.reta_query           = dpaa2_dev_rss_reta_query,
	.flow_ops_get         = dpaa2_dev_flow_ops_get,
	.rxq_info_get	      = dpaa2_rxq_info_get,
	.txq_info_get	      = dpaa2_txq_info_get,
	.tm_ops_get	      = dpaa2_tm_ops_get,
	.timesync_enable      = dpaa2_timesync_enable,
	.timesync_disable     = dpaa2_timesync_disable,
	.timesync_read_time   = dpaa2_timesync_read_time,
	.timesync_write_time  = dpaa2_timesync_write_time,
	.timesync_adjust_time = dpaa2_timesync_adjust_time,
	.timesync_read_rx_timestamp = dpaa2_timesync_read_rx_timestamp,
	.timesync_read_tx_timestamp = dpaa2_timesync_read_tx_timestamp,
	.mtr_ops_get = dpaa2_mtr_ops_get,
	.get_dcb_info = dpaa2_dev_dcb_info
};

/* Populate the mac address from physically available (u-boot/firmware) and/or
 * one set by higher layers like MC (restool) etc.
 * Returns the table of MAC entries (multiple entries)
 */
static int
populate_mac_addr(struct fsl_mc_io *dpni_dev,
	struct dpaa2_dev_priv *priv, struct rte_ether_addr *mac_entry)
{
	int ret = 0;
	struct rte_ether_addr phy_mac, prime_mac;

	memset(&phy_mac, 0, sizeof(struct rte_ether_addr));
	memset(&prime_mac, 0, sizeof(struct rte_ether_addr));

	/* Get the physical device MAC address */
	ret = dpni_get_port_mac_addr(dpni_dev, CMD_PRI_LOW, priv->token,
				     phy_mac.addr_bytes);
	if (ret) {
		DPAA2_PMD_ERR("DPNI get physical port MAC failed: %d", ret);
		goto cleanup;
	}

	ret = dpni_get_primary_mac_addr(dpni_dev, CMD_PRI_LOW, priv->token,
					prime_mac.addr_bytes);
	if (ret) {
		DPAA2_PMD_ERR("DPNI get Prime port MAC failed: %d", ret);
		goto cleanup;
	}

	/* Now that both MAC have been obtained, do:
	 *  if not_empty_mac(phy) && phy != Prime, overwrite prime with Phy
	 *     and return phy
	 *  If empty_mac(phy), return prime.
	 *  if both are empty, create random MAC, set as prime and return
	 */
	if (!rte_is_zero_ether_addr(&phy_mac)) {
		/* If the addresses are not same, overwrite prime */
		if (!rte_is_same_ether_addr(&phy_mac, &prime_mac)) {
			ret = dpni_set_primary_mac_addr(dpni_dev, CMD_PRI_LOW,
							priv->token,
							phy_mac.addr_bytes);
			if (ret) {
				DPAA2_PMD_ERR("Unable to set MAC Address: %d",
					      ret);
				goto cleanup;
			}
			prime_mac = phy_mac;
		}
	} else if (rte_is_zero_ether_addr(&prime_mac)) {
		/* In case phys and prime, both are zero, create random MAC */
		rte_eth_random_addr(prime_mac.addr_bytes);
		ret = dpni_set_primary_mac_addr(dpni_dev, CMD_PRI_LOW,
						priv->token,
						prime_mac.addr_bytes);
		if (ret) {
			DPAA2_PMD_ERR("Unable to set MAC Address: %d", ret);
			goto cleanup;
		}
	}

	/* prime_mac the final MAC address */
	*mac_entry = prime_mac;
	return 0;

cleanup:
	return ret;
}

static int
check_devargs_handler(__rte_unused const char *key, const char *value,
		      __rte_unused void *opaque)
{
	if (strcmp(value, "1"))
		return -1;

	return 0;
}

static int
dpaa2_get_devargs(struct rte_devargs *devargs, const char *key)
{
	struct rte_kvargs *kvlist;

	if (!devargs)
		return 0;

	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (!kvlist)
		return 0;

	if (!rte_kvargs_count(kvlist, key)) {
		rte_kvargs_free(kvlist);
		return 0;
	}

	if (rte_kvargs_process(kvlist, key,
			       check_devargs_handler, NULL) < 0) {
		rte_kvargs_free(kvlist);
		return 0;
	}
	rte_kvargs_free(kvlist);

	return 1;
}

/* Resolve the object this DPNI is wired to inside its DPRC container. The
 * endpoint decides whether MAC-level operations (link, promisc, flow control)
 * are available, and it is reported to the application by
 * rte_pmd_dpaa2_ep_name().
 */
static int
dpaa2_dev_ep_init(struct rte_dpaa2_device *dpaa2_dev,
		  struct dpaa2_dev_priv *priv)
{
	struct dpaa2_dprc_dev *dprc_node = dpaa2_dev->container;
	struct dprc_endpoint endpoint1, endpoint2;
	int link_state, ret;

	memset(&endpoint1, 0, sizeof(endpoint1));
	memset(&endpoint2, 0, sizeof(endpoint2));
	strlcpy(endpoint1.type, "dpni", sizeof(endpoint1.type));
	endpoint1.id = dpaa2_dev->object_id;
	ret = dprc_get_connection(&dprc_node->dprc, CMD_PRI_LOW,
				  dprc_node->token, &endpoint1, &endpoint2,
				  &link_state);
	if (ret != 0)
		return ret;

	if (strcmp(endpoint2.type, "dpmac") == 0)
		priv->ep_dev_type = DPAA2_MAC;
	else if (strcmp(endpoint2.type, "dpni") == 0)
		priv->ep_dev_type = DPAA2_ETH;
	else if (strcmp(endpoint2.type, "dpdmux") == 0)
		priv->ep_dev_type = DPAA2_MUX;
	else if (strcmp(endpoint2.type, "dpsw") == 0)
		priv->ep_dev_type = DPAA2_SW;
	else
		priv->ep_dev_type = DPAA2_UNKNOWN;

	priv->ep_object_id = endpoint2.id;

	/* dpdmux and dpsw endpoints are per-interface, so the interface index
	 * is part of the name.
	 */
	if (priv->ep_dev_type == DPAA2_MUX || priv->ep_dev_type == DPAA2_SW)
		snprintf(priv->ep_name, sizeof(priv->ep_name), "%s.%d.%d",
			 endpoint2.type, endpoint2.id, endpoint2.if_id);
	else
		snprintf(priv->ep_name, sizeof(priv->ep_name), "%s.%d",
			 endpoint2.type, endpoint2.id);

	return 0;
}

static int
dpaa2_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_device *dev = eth_dev->device;
	struct rte_dpaa2_device *dpaa2_dev;
	struct fsl_mc_io *dpni_dev;
	struct dpni_attr attr;
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct dpni_buffer_layout layout;
	int ret, hw_id, i, entry_num;
	struct dpaa2_flow_tbl_profile *tbl_profile;
	uint64_t iova;

	PMD_INIT_FUNC_TRACE();

	dpni_dev = rte_malloc(NULL, sizeof(struct fsl_mc_io), 0);
	if (!dpni_dev) {
		DPAA2_PMD_ERR("Memory allocation failed for dpni device");
		return -1;
	}
	dpni_dev->regs = dpaa2_get_mcp_ptr(MC_PORTAL_INDEX);
	eth_dev->process_private = dpni_dev;

	/* RX no prefetch mode? */
	if (dpaa2_get_devargs(dev->devargs, DRIVER_NO_PREFETCH_MODE)) {
		priv->flags |= DPAA2_NO_PREFETCH_RX;
		DPAA2_PMD_INFO("No RX prefetch mode");
	}

	if (dpaa2_get_devargs(dev->devargs, DRIVER_LOOPBACK_MODE)) {
		priv->flags |= DPAA2_RX_LOOPBACK_MODE;
		DPAA2_PMD_INFO("Rx loopback mode");
	}

	if (dpaa2_get_devargs(dev->devargs, DRIVER_NO_TAILDROP)) {
		priv->flags |= DPAA2_RX_TAILDROP_OFF;
		DPAA2_PMD_INFO("Rx taildrop disabled");
	}

	if (dpaa2_get_devargs(dev->devargs, DRIVER_NO_DATA_STASHING) ||
	    getenv("DPAA2_DATA_STASHING_OFF")) {
		priv->flags |= DPAA2_RX_DATA_STASHING_OFF_FLAG;
		DPAA2_PMD_INFO("Data stashing disabled");
	}

	/* For secondary processes, the primary has done all the work */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		/* In case of secondary, only burst and ops API need to be
		 * plugged.
		 */
		eth_dev->dev_ops = &dpaa2_ethdev_ops;
		eth_dev->rx_queue_count = dpaa2_dev_rx_queue_count;
		if (priv->flags & DPAA2_RX_LOOPBACK_MODE)
			eth_dev->rx_pkt_burst = dpaa2_dev_loopback_rx;
		else if (priv->flags & DPAA2_NO_PREFETCH_RX)
			eth_dev->rx_pkt_burst = dpaa2_dev_rx;
		else
			eth_dev->rx_pkt_burst = dpaa2_dev_prefetch_rx;
		eth_dev->tx_pkt_burst = dpaa2_dev_tx;
		return 0;
	}

	dpaa2_dev = RTE_CLASS_TO_BUS_DEVICE(eth_dev, *dpaa2_dev);

	hw_id = dpaa2_dev->object_id;
	ret = dpni_open(dpni_dev, CMD_PRI_LOW, hw_id, &priv->token);
	if (ret) {
		DPAA2_PMD_ERR(
			     "Failure in opening dpni@%d with err code %d",
			     hw_id, ret);
		rte_free(dpni_dev);
		return ret;
	}

	if (eth_dev->data->dev_conf.lpbk_mode)
		dpaa2_dev_recycle_deconfig(eth_dev);

	/* Clean the device first */
	ret = dpni_reset(dpni_dev, CMD_PRI_LOW, priv->token);
	if (ret) {
		DPAA2_PMD_ERR("Failure cleaning dpni@%d with err code %d",
			      hw_id, ret);
		goto init_err;
	}

	ret = dpni_get_attributes(dpni_dev, CMD_PRI_LOW, priv->token, &attr);
	if (ret) {
		DPAA2_PMD_ERR(
			     "Failure in get dpni@%d attribute, err code %d",
			     hw_id, ret);
		goto init_err;
	}

	ret = dpaa2_dev_ep_init(dpaa2_dev, priv);
	if (ret) {
		DPAA2_PMD_ERR("Failure in get dpni@%d endpoint, err code %d",
			      hw_id, ret);
		goto init_err;
	}

	ret = dpni_get_api_version(dpni_dev, CMD_PRI_LOW, &priv->dpni_ver_major,
				   &priv->dpni_ver_minor);
	if (ret) {
		DPAA2_PMD_ERR("Failure in get dpni@%d API version, err code %d",
			hw_id, ret);
		goto init_err;
	}

	priv->mc_rev = dpaa2_dev->bus_info->mc_rev;
	priv->num_rx_tc = attr.num_rx_tcs;
	priv->num_tx_tc = attr.num_tx_tcs;
	priv->qos_entries = attr.qos_entries;
	priv->fs_entries = attr.fs_entries;
	priv->dist_queues = attr.num_queues;
	priv->num_channels = attr.num_channels;
	priv->channel_inuse = 0;
	rte_spinlock_init(&priv->lpbk_qp_lock);

	/* only if the custom CG is enabled */
	if (attr.options & DPNI_OPT_CUSTOM_CG) {
		priv->max_cgs = attr.num_cgs;
		if (priv->max_cgs < priv->num_rx_tc) {
			DPAA2_PMD_WARN("DPNI%d has no enough cgids(%d) to set %d TCs",
				hw_id, priv->max_cgs, priv->num_rx_tc);
		}
	} else {
		priv->max_cgs = 0;
	}

	for (i = 0; i < priv->max_cgs; i++)
		priv->cgid_in_use[i] = 0;

	priv->nb_rx_queues = attr.num_rx_tcs * attr.num_queues;
	if (priv->nb_rx_queues > MAX_RX_QUEUES) {
		DPAA2_PMD_WARN("Too many RXQs(%d) > %d, reduce it to %d",
			priv->nb_rx_queues, MAX_RX_QUEUES, MAX_RX_QUEUES);
		priv->nb_rx_queues = MAX_RX_QUEUES;
	}
	if (attr.options & DPNI_OPT_SINGLE_SENDER)
		priv->nb_tx_queues = attr.num_tx_tcs * 1;
	else
		priv->nb_tx_queues = attr.num_tx_tcs * attr.num_queues;
	if (priv->nb_tx_queues > MAX_TX_QUEUES) {
		DPAA2_PMD_WARN("Too many TXQs(%d) > %d, reduce it to %d",
			priv->nb_tx_queues, MAX_TX_QUEUES, MAX_TX_QUEUES);
		priv->nb_tx_queues = MAX_TX_QUEUES;
	}
	if (priv->num_channels > DPAA2_MAX_CHANNELS) {
		DPAA2_PMD_WARN("Too many TX channels(%d) > %d, reduce it to %d",
			priv->num_channels, DPAA2_MAX_CHANNELS, DPAA2_MAX_CHANNELS);
		priv->num_channels = DPAA2_MAX_CHANNELS;
	}
	for (i = 0; i < priv->num_channels; i++)
		priv->tx_channels[i] = i;

	DPAA2_PMD_DEBUG("RX-TC= %d, rx_queues= %d, tx_queues=%d, max_cgs=%d",
			priv->num_rx_tc, priv->nb_rx_queues,
			priv->nb_tx_queues, priv->max_cgs);

	priv->hw = dpni_dev;
	priv->hw_id = hw_id;
	priv->options = attr.options;
	priv->max_mac_filters = attr.mac_filter_entries;
	priv->max_vlan_filters = attr.vlan_filter_entries;
	priv->tx_conf_type = DPAA2_TX_NO_CONF;

	/* Used with ``fslmc:dpni.1,drv_tx_conf=1`` */
	if (dpaa2_get_devargs(dev->devargs, DRIVER_TX_CONF)) {
		priv->tx_conf_type = DPAA2_TX_ABSOLUTE_CONF;
		DPAA2_PMD_INFO("TX_ABSOLUTE_CONF Enabled");
	} else if (dpaa2_get_devargs(dev->devargs, DRIVER_TX_DYNAMIC_CONF)) {
		priv->tx_conf_type = DPAA2_TX_DYNAMIC_CONF;
		DPAA2_PMD_INFO("TX_DYNAMIC_CONF Enabled");
		priv->flags |= DPAA2_TX_PREFETCH_DYNAMIC_CONF;
		if (dpaa2_get_devargs(dev->devargs, DRIVER_TX_DYNAMIC_CONF_PREFETCH))
			priv->flags &= ~DPAA2_TX_PREFETCH_DYNAMIC_CONF;

		DPAA2_PMD_INFO("Tx dynamic prefetch confirm %s",
			(priv->flags & DPAA2_TX_PREFETCH_DYNAMIC_CONF) ?
			"enabled" : "disabled");
	}

	if (dpaa2_get_devargs(dev->devargs, DRIVER_ERROR_QUEUE)) {
		priv->flags |= DPAA2_RX_ERROR_QUEUE_FLAG;
		DPAA2_PMD_INFO("Enable error queue");
	}

	/* Packets with parse error to be dropped in hw */
	if (dpaa2_get_devargs(dev->devargs, DRIVER_RX_PARSE_ERR_DROP)) {
		priv->flags |= DPAA2_PARSE_ERR_DROP;
		DPAA2_PMD_INFO("Drop parse error packets in hw");
	}

	if (getenv("DPAA2_PRINT_RX_PARSER_RESULT"))
		priv->flags |= DPAA2_RX_PRINT_PSR_RESULT_FLAG;

	/* Allocate memory for hardware structure for queues */
	ret = dpaa2_alloc_rx_tx_queues(eth_dev);
	if (ret) {
		DPAA2_PMD_ERR("Queue allocation Failed");
		goto init_err;
	}

	for (i = 0; i < priv->num_channels; i++) {
		/*Set tx-conf and error configuration*/
		if (priv->tx_conf_type == DPAA2_TX_ABSOLUTE_CONF) {
			ret = dpni_set_tx_confirmation_mode(dpni_dev,
				CMD_PRI_LOW, priv->token, i, DPNI_CONF_AFFINE);
		} else {
			ret = dpni_set_tx_confirmation_mode(dpni_dev,
				CMD_PRI_LOW, priv->token, i, DPNI_CONF_DISABLE);
		}
		if (ret) {
			DPAA2_PMD_ERR("Error(%d) in tx conf setting", ret);
			goto init_err;
		}
	}

	/* Allocate memory for storing MAC addresses.
	 * Table of mac_filter_entries size is allocated so that RTE ether lib
	 * can add MAC entries when rte_eth_dev_mac_addr_add is called.
	 */
	eth_dev->data->mac_addrs = rte_zmalloc("dpni",
		RTE_ETHER_ADDR_LEN * attr.mac_filter_entries, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		DPAA2_PMD_ERR(
		   "Failed to allocate %d bytes needed to store MAC addresses",
		   RTE_ETHER_ADDR_LEN * attr.mac_filter_entries);
		ret = -ENOMEM;
		goto init_err;
	}

	ret = populate_mac_addr(dpni_dev, priv, &eth_dev->data->mac_addrs[0]);
	if (ret) {
		DPAA2_PMD_ERR("Unable to fetch MAC Address for device");
		rte_free(eth_dev->data->mac_addrs);
		eth_dev->data->mac_addrs = NULL;
		goto init_err;
	}

	/* ... tx buffer layout ... */
	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	if (priv->tx_conf_type != DPAA2_TX_NO_CONF) {
		layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
		layout.pass_timestamp = true;
	}
	layout.options |= DPNI_BUF_LAYOUT_OPT_FRAME_STATUS;
	layout.pass_frame_status = 1;
	ret = dpni_set_buffer_layout(dpni_dev, CMD_PRI_LOW, priv->token,
			DPNI_QUEUE_TX, &layout);
	if (ret) {
		DPAA2_PMD_ERR("Error (%d) in setting tx buffer layout", ret);
		goto init_err;
	}
	ret = dpni_set_buffer_layout(dpni_dev, CMD_PRI_LOW, priv->token,
			DPNI_QUEUE_TX_CONFIRM, &layout);
	if (ret) {
		DPAA2_PMD_ERR("Error (%d) in setting tx conf buffer layout", ret);
		goto init_err;
	}

	eth_dev->dev_ops = &dpaa2_ethdev_ops;
	eth_dev->rx_queue_count = dpaa2_dev_rx_queue_count;

	if (dpaa2_get_devargs(dev->devargs, DRIVER_LOOPBACK_MODE)) {
		eth_dev->rx_pkt_burst = dpaa2_dev_loopback_rx;
		DPAA2_PMD_INFO("Loopback mode");
	} else if (dpaa2_get_devargs(dev->devargs, DRIVER_NO_PREFETCH_MODE)) {
		eth_dev->rx_pkt_burst = dpaa2_dev_rx;
		DPAA2_PMD_INFO("No Prefetch mode");
	} else {
		eth_dev->rx_pkt_burst = dpaa2_dev_prefetch_rx;
	}
	eth_dev->tx_pkt_burst = dpaa2_dev_tx;

	/* Init fields w.r.t. classification */
	for (i = 0; i < (MAX_TCS + 1); i++) {
		if (i < MAX_TCS) {
			tbl_profile = &priv->flow_profile.tc_profile[i];
			entry_num = priv->fs_entries;
		} else {
			tbl_profile = &priv->flow_profile.qos_profile;
			entry_num = priv->qos_entries;
		}
		memset(tbl_profile, 0, sizeof(struct dpaa2_flow_tbl_profile));
		tbl_profile->extract_param = rte_zmalloc(NULL,
			DPAA2_EXTRACT_PARAM_MAX_SIZE,
			RTE_CACHE_LINE_SIZE);
		if (!tbl_profile->extract_param)
			goto init_err;
		iova = DPAA2_VADDR_TO_IOVA_AND_CHECK(tbl_profile->extract_param,
			DPAA2_EXTRACT_PARAM_MAX_SIZE);
		tbl_profile->default_drop = false;
		if (i < MAX_TCS) {
			tbl_profile->tc_cfg.dist_size = priv->dist_queues;
			tbl_profile->tc_cfg.key_cfg_iova = iova;
			tbl_profile->tc_cfg.tc = i;
			/** First flow of TC as default flow, otherwise, may be dropped.*/
			tbl_profile->default_queue.index = priv->dist_queues * i;
		} else {
			tbl_profile->qos_cfg.key_cfg_iova = iova;
			tbl_profile->qos_cfg.keep_entries = true;
			/** First TC as default TC, otherwise, may be dropped.*/
			tbl_profile->default_jump.group = 0;
		}
		if (!entry_num)
			continue;

		tbl_profile->entry_map = rte_zmalloc(NULL, entry_num / 8 + 1, 0);
		if (!tbl_profile->entry_map)
			goto init_err;
	}

	for (i = 0; i < priv->num_rx_tc; i++) {
		if (i >= RTE_ETH_DCB_NUM_USER_PRIORITIES)
			break;
		if (i >= priv->qos_entries)
			break;
		priv->prio_dcb_tc[i] = i;
	}
	priv->nb_dcb_tcs = i;

	ret = dpni_set_max_frame_length(dpni_dev, CMD_PRI_LOW, priv->token,
					RTE_ETHER_MAX_LEN - RTE_ETHER_CRC_LEN
					+ VLAN_TAG_SIZE);
	if (ret) {
		DPAA2_PMD_ERR("Unable to set mtu. check config");
		goto init_err;
	}
	eth_dev->data->mtu = RTE_ETHER_MTU;

	priv->sp_protocol = dpaa2_dev->bus_info->sp_protocol;

	DPAA2_PMD_INFO("%s: netdev created, connected to %s",
		eth_dev->data->name, priv->ep_name);

	priv->speed_capa = dpaa2_dev_get_speed_capability(eth_dev);

	return 0;
init_err:
	dpaa2_dev_close(eth_dev);

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_dpaa2_dev_is_dpaa2, 24.11)
int
rte_pmd_dpaa2_dev_is_dpaa2(uint32_t eth_id)
{
	struct rte_eth_dev *dev;

	if (eth_id >= RTE_MAX_ETHPORTS)
		return false;

	dev = &rte_eth_devices[eth_id];
	if (!dev->device)
		return false;

	return dev->device->driver == &rte_dpaa2_pmd.driver;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_dpaa2_ep_name, 24.11)
const char *
rte_pmd_dpaa2_ep_name(uint32_t eth_id)
{
	struct rte_eth_dev *dev;
	struct dpaa2_dev_priv *priv;

	if (eth_id >= RTE_MAX_ETHPORTS)
		return NULL;

	if (!rte_pmd_dpaa2_dev_is_dpaa2(eth_id))
		return NULL;

	dev = &rte_eth_devices[eth_id];
	if (!dev->data)
		return NULL;

	if (!dev->data->dev_private)
		return NULL;

	priv = dev->data->dev_private;

	return priv->ep_name;
}

static int dpaa2_tx_sg_pool_init(void)
{
	char name[RTE_MEMZONE_NAMESIZE];

	if (dpaa2_tx_sg_pool)
		return 0;

	sprintf(name, "dpaa2_mbuf_tx_sg_pool");
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		dpaa2_tx_sg_pool = rte_pktmbuf_pool_create(name,
			DPAA2_POOL_SIZE,
			DPAA2_POOL_CACHE_SIZE, 0,
			DPAA2_MAX_SGS * sizeof(struct qbman_sge),
			rte_socket_id());
		if (!dpaa2_tx_sg_pool) {
			DPAA2_PMD_ERR("SG pool creation failed");
			return -ENOMEM;
		}
	} else {
		dpaa2_tx_sg_pool = rte_mempool_lookup(name);
		if (!dpaa2_tx_sg_pool) {
			DPAA2_PMD_ERR("SG pool lookup failed");
			return -ENOMEM;
		}
	}

	return 0;
}

static int
rte_dpaa2_probe(struct rte_dpaa2_driver *dpaa2_drv,
		struct rte_dpaa2_device *dpaa2_dev)
{
	struct rte_eth_dev *eth_dev;
	struct dpaa2_dev_priv *dev_priv;
	int diag;

	if ((DPAA2_MBUF_HW_ANNOTATION + DPAA2_FD_PTA_SIZE) >
		RTE_PKTMBUF_HEADROOM) {
		DPAA2_PMD_ERR("RTE_PKTMBUF_HEADROOM(%d) < DPAA2 Annotation(%d)",
			RTE_PKTMBUF_HEADROOM,
			DPAA2_MBUF_HW_ANNOTATION + DPAA2_FD_PTA_SIZE);

		return -EINVAL;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		eth_dev = rte_eth_dev_allocate(dpaa2_dev->device.name);
		if (!eth_dev)
			return -ENODEV;
		dev_priv = rte_zmalloc("ethdev private structure",
				       sizeof(struct dpaa2_dev_priv),
				       RTE_CACHE_LINE_SIZE);
		if (dev_priv == NULL) {
			DPAA2_PMD_CRIT(
				"Unable to allocate memory for private data");
			rte_eth_dev_release_port(eth_dev);
			return -ENOMEM;
		}
		eth_dev->data->dev_private = (void *)dev_priv;
		/* Store a pointer to eth_dev in dev_private */
		dev_priv->eth_dev = eth_dev;
	} else {
		eth_dev = rte_eth_dev_attach_secondary(dpaa2_dev->device.name);
		if (!eth_dev) {
			DPAA2_PMD_DEBUG("returning enodev");
			return -ENODEV;
		}
	}

	eth_dev->device = &dpaa2_dev->device;

	eth_dev->data->rx_mbuf_alloc_failed = 0;

	if (dpaa2_drv->drv_flags & RTE_DPAA2_DRV_INTR_LSC)
		eth_dev->data->dev_flags |= RTE_ETH_DEV_INTR_LSC;

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	/* Invoke PMD device initialization function */
	diag = dpaa2_dev_init(eth_dev);
	if (!diag) {
		diag = dpaa2_tx_sg_pool_init();
		if (diag)
			return diag;
		rte_eth_dev_probing_finish(eth_dev);
		dpaa2_valid_dev++;
		return 0;
	}

	rte_eth_dev_release_port(eth_dev);
	return diag;
}

static int
rte_dpaa2_remove(struct rte_dpaa2_device *dpaa2_dev)
{
	struct rte_eth_dev *eth_dev;
	int ret = 0;

	eth_dev = rte_eth_dev_allocated(dpaa2_dev->device.name);
	if (eth_dev) {
		ret = dpaa2_dev_close(eth_dev);
		if (ret)
			DPAA2_PMD_ERR("dpaa2_dev_close ret= %d", ret);

		ret = rte_eth_dev_release_port(eth_dev);
	}

	dpaa2_valid_dev--;
	if (!dpaa2_valid_dev) {
		rte_mempool_free(dpaa2_tx_sg_pool);
		dpaa2_tx_sg_pool = NULL;
	}

	return ret;
}

static struct rte_dpaa2_driver rte_dpaa2_pmd = {
	.drv_flags = RTE_DPAA2_DRV_INTR_LSC | RTE_DPAA2_DRV_IOVA_AS_VA,
	.drv_type = DPAA2_ETH,
	.probe = rte_dpaa2_probe,
	.remove = rte_dpaa2_remove,
};

RTE_PMD_REGISTER_DPAA2(NET_DPAA2_PMD_DRIVER_NAME, rte_dpaa2_pmd);
RTE_PMD_REGISTER_PARAM_STRING(NET_DPAA2_PMD_DRIVER_NAME,
		DRIVER_LOOPBACK_MODE "=<int> "
		DRIVER_NO_PREFETCH_MODE "=<int>"
		DRIVER_TX_CONF "=<int>"
		DRIVER_TX_DYNAMIC_CONF "=<int>"
		DRIVER_TX_DYNAMIC_CONF_PREFETCH "=<int>"
		DRIVER_RX_PARSE_ERR_DROP "=<int>"
		DRIVER_ERROR_QUEUE "=<int>"
		DRIVER_NO_TAILDROP "=<int>"
		DRIVER_NO_DATA_STASHING "=<int>");
RTE_LOG_REGISTER_DEFAULT(dpaa2_logtype_pmd, NOTICE);
