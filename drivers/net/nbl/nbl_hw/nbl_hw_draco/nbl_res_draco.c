/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Nebulamatrix Technology Co., Ltd.
 */

#include "nbl_res_draco.h"

static const struct nbl_xstats_name nbl_stats_strings[] = {
	{"eth_rx_prio0_packets", 32},
	{"eth_rx_prio0_bytes", 48},
	{"eth_rx_prio0_drop_packets", 32},
	{"eth_tx_prio0_packets", 32},
	{"eth_tx_prio0_bytes", 48},
	{"eth_tx_prio0_drop_packets", 32},
	{"eth_rx_prio1_packets", 32},
	{"eth_rx_prio1_bytes", 48},
	{"eth_rx_prio1_drop_packets", 32},
	{"eth_tx_prio1_packets", 32},
	{"eth_tx_prio1_bytes", 48},
	{"eth_tx_prio1_drop_packets", 32},
	{"eth_rx_prio2_packets", 32},
	{"eth_rx_prio2_bytes", 48},
	{"eth_rx_prio2_drop_packets", 32},
	{"eth_tx_prio2_packets", 32},
	{"eth_tx_prio2_bytes", 48},
	{"eth_tx_prio2_drop_packets", 32},
	{"eth_rx_prio3_packets", 32},
	{"eth_rx_prio3_bytes", 48},
	{"eth_rx_prio3_drop_packets", 32},
	{"eth_tx_prio3_packets", 32},
	{"eth_tx_prio3_bytes", 48},
	{"eth_tx_prio3_drop_packets", 32},
	{"eth_rx_prio4_packets", 32},
	{"eth_rx_prio4_bytes", 48},
	{"eth_rx_prio4_drop_packets", 32},
	{"eth_tx_prio4_packets", 32},
	{"eth_tx_prio4_bytes", 48},
	{"eth_tx_prio4_drop_packets", 32},
	{"eth_rx_prio5_packets", 32},
	{"eth_rx_prio5_bytes", 48},
	{"eth_rx_prio5_drop_packets", 32},
	{"eth_tx_prio5_packets", 32},
	{"eth_tx_prio5_bytes", 48},
	{"eth_tx_prio5_drop_packets", 32},
	{"eth_rx_prio6_packets", 32},
	{"eth_rx_prio6_bytes", 48},
	{"eth_rx_prio6_drop_packets", 32},
	{"eth_tx_prio6_packets", 32},
	{"eth_tx_prio6_bytes", 48},
	{"eth_tx_prio6_drop_packets", 32},
	{"eth_rx_prio7_packets", 32},
	{"eth_rx_prio7_bytes", 48},
	{"eth_rx_prio7_drop_packets", 32},
	{"eth_tx_prio7_packets", 32},
	{"eth_tx_prio7_bytes", 48},
	{"eth_tx_prio7_drop_packets", 32},
	{"eth_frames_txd", 64},
	{"eth_frames_txd_ok", 64},
	{"eth_unicast_frames_txd", 64},
	{"eth_multicast_frames_txd", 64},
	{"eth_multicast_frames_txd_ok", 64},
	{"eth_broadcast_frames_txd", 64},
	{"eth_broadcast_frames_txd_ok", 64},
	{"eth_underflow_error_frames_txd", 64},
	{"eth_pause_frames_txd", 64},
	{"eth_vlan_frames_txd", 64},
	{"eth_frames_txd_64B", 64},
	{"eth_frames_txd_65_to_127B", 64},
	{"eth_frames_txd_128_to_255B", 64},
	{"eth_frames_txd_256_to_511B", 64},
	{"eth_frames_txd_512_to_1023B", 64},
	{"eth_frames_txd_1024_to_MAXB", 64},
	{"eth_octets_txd", 64},
	{"eth_frames_rxd", 64},
	{"eth_undersize_frames_rxd_good", 64},
	{"eth_oversize_frames_rxd_good", 64},
	{"eth_unicast_frames_rxd_ok", 64},
	{"eth_multicast_frames_rxd_ok", 64},
	{"eth_broadcast_frames_rxd_ok", 64},
	{"eth_crc_error_frames_rxd", 64},
	{"eth_runt_error_frames_rxd", 64},
	{"eth_jabber_error_frames_rxd", 64},
	{"eth_length_error_frames_rxd", 64},
	{"eth_out_of_range_type_frames_rxd", 64},
	{"eth_pause_frames_rxd", 64},
	{"eth_vlan_frames_rxd", 64},
	{"eth_watchdog_error_frames_rxd", 64},
	{"eth_frames_rxd_64B", 64},
	{"eth_frames_rxd_65_to_127B", 64},
	{"eth_frames_rxd_128_to_255B", 64},
	{"eth_frames_rxd_256_to_511B", 64},
	{"eth_frames_rxd_512_to_1023B", 64},
	{"eth_frames_rxd_1024_to_MAXB", 64},
	{"eth_octets_rxd", 64},
	{"eth_octets_rxd_ok", 64},
};

static int nbl_get_xstats_cnt(void *priv, u16 *xstats_cnt)
{
	RTE_SET_USED(priv);
	*xstats_cnt = ARRAY_SIZE(nbl_stats_strings);
	return 0;
}

static int nbl_get_xstats_bits(void *priv, u8 *bits, u16 count)
{
	u16 i;

	RTE_SET_USED(priv);
	if (count > ARRAY_SIZE(nbl_stats_strings))
		return -EINVAL;

	for (i = 0; i < count; i++)
		bits[i] = nbl_stats_strings[i].bits;
	return 0;
}

static int nbl_get_xstats_names(void *priv,
				struct rte_eth_xstat_name *xstats_names,
				u16 need_xstats_cnt, u16 *xstats_cnt)
{
	u32 i = 0;
	u16 count = *xstats_cnt;

	RTE_SET_USED(priv);

	if (need_xstats_cnt > ARRAY_SIZE(nbl_stats_strings))
		return -EINVAL;

	for (i = 0; i < need_xstats_cnt; i++) {
		strlcpy(xstats_names[count].name, nbl_stats_strings[i].name,
			sizeof(xstats_names[count].name));
		count++;
	}
	*xstats_cnt = count;
	return 0;
}

static struct nbl_resource_ops nbl_res_ops = {
	.get_hw_xstats_cnt = nbl_get_xstats_cnt,
	.get_hw_xstats_bits = nbl_get_xstats_bits,
	.get_hw_xstats_names = nbl_get_xstats_names,
};

static bool is_ops_inited;

static void nbl_res_remove_ops(struct nbl_resource_ops_tbl **res_ops_tbl)
{
	free(*res_ops_tbl);
	*res_ops_tbl = NULL;
}

static int nbl_res_setup_ops(struct nbl_resource_ops_tbl **res_ops_tbl,
			     struct nbl_resource_mgt_draco *res_mgt_draco)
{
	int ret = 0;

	*res_ops_tbl = calloc(1, sizeof(struct nbl_resource_ops_tbl));
	if (!*res_ops_tbl)
		return -ENOMEM;

	if (!is_ops_inited) {
		ret = nbl_txrx_setup_ops(&nbl_res_ops);
		if (ret)
			goto set_ops_failed;

		is_ops_inited = true;
	}

	NBL_RES_OPS_TBL_TO_OPS(*res_ops_tbl) = &nbl_res_ops;
	NBL_RES_OPS_TBL_TO_PRIV(*res_ops_tbl) = res_mgt_draco;

	return ret;

set_ops_failed:
	nbl_res_remove_ops(res_ops_tbl);
	return ret;
}

static void nbl_res_stop(struct nbl_resource_mgt_draco *res_mgt_draco)
{
	struct nbl_resource_mgt *res_mgt = &res_mgt_draco->res_mgt;
	nbl_txrx_mgt_stop(res_mgt);
}

static int nbl_res_start(struct nbl_resource_mgt_draco *res_mgt_draco)
{
	struct nbl_resource_mgt *res_mgt = &res_mgt_draco->res_mgt;
	const struct nbl_hw_ops *hw_ops = NBL_RES_MGT_TO_HW_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 func_id, mgt_pf;
	int ret;

	ret = hw_ops->capture_bdf(NBL_RES_MGT_TO_HW_PRIV(res_mgt), &func_id, &mgt_pf);
	if (ret)
		return ret;
	common->mgt_pf = mgt_pf;
	res_mgt->res_info.base_qid = 0;

	return nbl_txrx_mgt_start(res_mgt);
}

static void
nbl_res_remove_res_mgt(struct nbl_resource_mgt_draco **res_mgt_draco)
{
	rte_free(*res_mgt_draco);
	*res_mgt_draco = NULL;
}

static int
nbl_res_setup_res_mgt(struct nbl_resource_mgt_draco **res_mgt_draco)
{
	*res_mgt_draco = rte_zmalloc("nbl_res_mgt",
				      sizeof(struct nbl_resource_mgt_draco),
				      0);
	if (!*res_mgt_draco)
		return -ENOMEM;

	return 0;
}

int nbl_res_init_draco(void *p, struct rte_eth_dev *eth_dev)
{
	struct nbl_resource_mgt_draco **res_mgt_draco;
	struct nbl_resource_ops_tbl **res_ops_tbl;
	struct nbl_hw_ops_tbl *hw_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	int ret = 0;

	res_mgt_draco = (struct nbl_resource_mgt_draco **)&NBL_ADAPTER_TO_RES_MGT(adapter);
	res_ops_tbl = &NBL_ADAPTER_TO_RES_OPS_TBL(adapter);
	hw_ops_tbl = NBL_ADAPTER_TO_HW_OPS_TBL(adapter);
	chan_ops_tbl = NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);

	ret = nbl_res_setup_res_mgt(res_mgt_draco);
	if (ret)
		goto setup_mgt_fail;

	NBL_RES_MGT_TO_CHAN_OPS_TBL(&(*res_mgt_draco)->res_mgt) = chan_ops_tbl;
	NBL_RES_MGT_TO_HW_OPS_TBL(&(*res_mgt_draco)->res_mgt) = hw_ops_tbl;
	NBL_RES_MGT_TO_ETH_DEV(&(*res_mgt_draco)->res_mgt) = eth_dev;
	NBL_RES_MGT_TO_COMMON(&(*res_mgt_draco)->res_mgt) = &adapter->common;

	ret = nbl_res_start(*res_mgt_draco);
	if (ret)
		goto start_fail;

	ret = nbl_res_setup_ops(res_ops_tbl, *res_mgt_draco);
	if (ret)
		goto setup_ops_fail;

	return 0;

setup_ops_fail:
	nbl_res_stop(*res_mgt_draco);
start_fail:
	nbl_res_remove_res_mgt(res_mgt_draco);
setup_mgt_fail:
	return ret;
}

void nbl_res_remove_draco(void *p)
{
	struct nbl_resource_mgt_draco **res_mgt_draco;
	struct nbl_resource_ops_tbl **res_ops_tbl;
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;

	res_mgt_draco = (struct nbl_resource_mgt_draco **)&NBL_ADAPTER_TO_RES_MGT(adapter);
	res_ops_tbl = &NBL_ADAPTER_TO_RES_OPS_TBL(adapter);

	nbl_res_remove_ops(res_ops_tbl);
	nbl_res_stop(*res_mgt_draco);
	nbl_res_remove_res_mgt(res_mgt_draco);
}
