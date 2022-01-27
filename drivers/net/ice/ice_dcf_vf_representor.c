/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <errno.h>
#include <sys/types.h>

#include <rte_ethdev.h>

#include "ice_dcf_ethdev.h"
#include "ice_rxtx.h"

#define ICE_DCF_REPR_32_BIT_WIDTH (CHAR_BIT * 4)
#define ICE_DCF_REPR_48_BIT_WIDTH (CHAR_BIT * 6)
#define ICE_DCF_REPR_48_BIT_MASK  RTE_LEN2MASK(ICE_DCF_REPR_48_BIT_WIDTH, uint64_t)
static uint16_t
ice_dcf_vf_repr_rx_burst(__rte_unused void *rxq,
			 __rte_unused struct rte_mbuf **rx_pkts,
			 __rte_unused uint16_t nb_pkts)
{
	return 0;
}

static uint16_t
ice_dcf_vf_repr_tx_burst(__rte_unused void *txq,
			 __rte_unused struct rte_mbuf **tx_pkts,
			 __rte_unused uint16_t nb_pkts)
{
	return 0;
}

static int
ice_dcf_vf_repr_dev_configure(struct rte_eth_dev *dev)
{
	ice_dcf_vf_repr_init_vlan(dev);

	return 0;
}

static int
ice_dcf_vf_repr_dev_start(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;

	return 0;
}

static int
ice_dcf_vf_repr_dev_stop(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;

	return 0;
}

static int
ice_dcf_vf_repr_dev_close(struct rte_eth_dev *dev)
{
	return ice_dcf_vf_repr_uninit(dev);
}

static int
ice_dcf_vf_repr_rx_queue_setup(__rte_unused struct rte_eth_dev *dev,
			       __rte_unused uint16_t queue_id,
			       __rte_unused uint16_t nb_desc,
			       __rte_unused unsigned int socket_id,
			       __rte_unused const struct rte_eth_rxconf *conf,
			       __rte_unused struct rte_mempool *pool)
{
	return 0;
}

static int
ice_dcf_vf_repr_tx_queue_setup(__rte_unused struct rte_eth_dev *dev,
			       __rte_unused uint16_t queue_id,
			       __rte_unused uint16_t nb_desc,
			       __rte_unused unsigned int socket_id,
			       __rte_unused const struct rte_eth_txconf *conf)
{
	return 0;
}

static int
ice_dcf_vf_repr_promiscuous_enable(__rte_unused struct rte_eth_dev *ethdev)
{
	return 0;
}

static int
ice_dcf_vf_repr_promiscuous_disable(__rte_unused struct rte_eth_dev *ethdev)
{
	return 0;
}

static int
ice_dcf_vf_repr_allmulticast_enable(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

static int
ice_dcf_vf_repr_allmulticast_disable(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

static int
ice_dcf_vf_repr_link_update(__rte_unused struct rte_eth_dev *ethdev,
			    __rte_unused int wait_to_complete)
{
	return 0;
}

static __rte_always_inline struct ice_dcf_hw *
ice_dcf_vf_repr_hw(struct ice_dcf_vf_repr *repr)
{
	struct ice_dcf_adapter *dcf_adapter =
			repr->dcf_eth_dev->data->dev_private;

	if (!dcf_adapter) {
		PMD_DRV_LOG(ERR, "DCF for VF representor has been released\n");
		return NULL;
	}

	return &dcf_adapter->real_hw;
}

static int
ice_dcf_vf_repr_dev_info_get(struct rte_eth_dev *dev,
			     struct rte_eth_dev_info *dev_info)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct ice_dcf_hw *dcf_hw = ice_dcf_vf_repr_hw(repr);

	if (!dcf_hw)
		return -EIO;

	dev_info->device = dev->device;
	dev_info->max_mac_addrs = ICE_NUM_MACADDR_MAX;
	dev_info->max_rx_queues = dcf_hw->vsi_res->num_queue_pairs;
	dev_info->max_tx_queues = dcf_hw->vsi_res->num_queue_pairs;
	dev_info->min_rx_bufsize = ICE_BUF_SIZE_MIN;
	dev_info->max_rx_pktlen = ICE_FRAME_SIZE_MAX;
	dev_info->hash_key_size = dcf_hw->vf_res->rss_key_size;
	dev_info->reta_size = dcf_hw->vf_res->rss_lut_size;
	dev_info->flow_type_rss_offloads = ICE_RSS_OFFLOAD_ALL;

	dev_info->rx_offload_capa =
		RTE_ETH_RX_OFFLOAD_VLAN_STRIP |
		RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
		RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
		RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
		RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
		RTE_ETH_RX_OFFLOAD_SCATTER |
		RTE_ETH_RX_OFFLOAD_VLAN_FILTER |
		RTE_ETH_RX_OFFLOAD_VLAN_EXTEND |
		RTE_ETH_RX_OFFLOAD_RSS_HASH;
	dev_info->tx_offload_capa =
		RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM |
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM |
		RTE_ETH_TX_OFFLOAD_TCP_TSO |
		RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_thresh = {
			.pthresh = ICE_DEFAULT_RX_PTHRESH,
			.hthresh = ICE_DEFAULT_RX_HTHRESH,
			.wthresh = ICE_DEFAULT_RX_WTHRESH,
		},
		.rx_free_thresh = ICE_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_thresh = {
			.pthresh = ICE_DEFAULT_TX_PTHRESH,
			.hthresh = ICE_DEFAULT_TX_HTHRESH,
			.wthresh = ICE_DEFAULT_TX_WTHRESH,
		},
		.tx_free_thresh = ICE_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = ICE_DEFAULT_TX_RSBIT_THRESH,
		.offloads = 0,
	};

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = ICE_MAX_RING_DESC,
		.nb_min = ICE_MIN_RING_DESC,
		.nb_align = ICE_ALIGN_RING_DESC,
	};

	dev_info->tx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = ICE_MAX_RING_DESC,
		.nb_min = ICE_MIN_RING_DESC,
		.nb_align = ICE_ALIGN_RING_DESC,
	};

	dev_info->switch_info.name = dcf_hw->eth_dev->device->name;
	dev_info->switch_info.domain_id = repr->switch_domain_id;
	dev_info->switch_info.port_id = repr->vf_id;

	return 0;
}

static __rte_always_inline bool
ice_dcf_vlan_offload_ena(struct ice_dcf_vf_repr *repr)
{
	return !!(ice_dcf_vf_repr_hw(repr)->vf_res->vf_cap_flags &
		  VIRTCHNL_VF_OFFLOAD_VLAN_V2);
}

static int
ice_dcf_vlan_offload_config(struct ice_dcf_vf_repr *repr,
			    struct virtchnl_dcf_vlan_offload *vlan_offload)
{
	struct dcf_virtchnl_cmd args;
	int err;

	memset(&args, 0, sizeof(args));
	args.v_op = VIRTCHNL_OP_DCF_VLAN_OFFLOAD;
	args.req_msg = (uint8_t *)vlan_offload;
	args.req_msglen = sizeof(*vlan_offload);

	err = ice_dcf_execute_virtchnl_cmd(ice_dcf_vf_repr_hw(repr), &args);
	if (err)
		PMD_DRV_LOG(ERR,
			    "Failed to execute command of VIRTCHNL_OP_DCF_VLAN_OFFLOAD");

	return err;
}

static int
ice_dcf_vf_repr_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	struct virtchnl_dcf_vlan_offload vlan_offload;
	int err;

	if (!ice_dcf_vlan_offload_ena(repr))
		return -ENOTSUP;

	/* Vlan stripping setting */
	if (mask & RTE_ETH_VLAN_STRIP_MASK) {
		bool enable = !!(dev_conf->rxmode.offloads &
				 RTE_ETH_RX_OFFLOAD_VLAN_STRIP);

		if (enable && repr->outer_vlan_info.port_vlan_ena) {
			PMD_DRV_LOG(ERR,
				    "Disable the port VLAN firstly\n");
			return -EINVAL;
		}

		memset(&vlan_offload, 0, sizeof(vlan_offload));

		if (enable)
			vlan_offload.vlan_flags =
					VIRTCHNL_DCF_VLAN_STRIP_INTO_RX_DESC <<
					VIRTCHNL_DCF_VLAN_STRIP_MODE_S;
		else if (repr->outer_vlan_info.stripping_ena && !enable)
			vlan_offload.vlan_flags =
					VIRTCHNL_DCF_VLAN_STRIP_DISABLE <<
					VIRTCHNL_DCF_VLAN_STRIP_MODE_S;

		if (vlan_offload.vlan_flags) {
			vlan_offload.vf_id = repr->vf_id;
			vlan_offload.tpid = repr->outer_vlan_info.tpid;
			vlan_offload.vlan_flags |=
					VIRTCHNL_DCF_VLAN_TYPE_OUTER <<
					VIRTCHNL_DCF_VLAN_TYPE_S;

			err = ice_dcf_vlan_offload_config(repr, &vlan_offload);
			if (err)
				return -EIO;

			repr->outer_vlan_info.stripping_ena = enable;
		}
	}

	return 0;
}

static int
ice_dcf_vf_repr_vlan_pvid_set(struct rte_eth_dev *dev,
			      uint16_t pvid, int on)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct virtchnl_dcf_vlan_offload vlan_offload;
	int err;

	if (!ice_dcf_vlan_offload_ena(repr))
		return -ENOTSUP;

	if (repr->outer_vlan_info.stripping_ena) {
		PMD_DRV_LOG(ERR,
			    "Disable the VLAN stripping firstly\n");
		return -EINVAL;
	}

	if (pvid > RTE_ETHER_MAX_VLAN_ID)
		return -EINVAL;

	memset(&vlan_offload, 0, sizeof(vlan_offload));

	if (on)
		vlan_offload.vlan_flags =
				(VIRTCHNL_DCF_VLAN_INSERT_PORT_BASED <<
				 VIRTCHNL_DCF_VLAN_INSERT_MODE_S);
	else
		vlan_offload.vlan_flags =
				(VIRTCHNL_DCF_VLAN_INSERT_DISABLE <<
				 VIRTCHNL_DCF_VLAN_INSERT_MODE_S);

	vlan_offload.vf_id = repr->vf_id;
	vlan_offload.tpid = repr->outer_vlan_info.tpid;
	vlan_offload.vlan_flags |= (VIRTCHNL_DCF_VLAN_TYPE_OUTER <<
				    VIRTCHNL_DCF_VLAN_TYPE_S);
	vlan_offload.vlan_id = pvid;

	err = ice_dcf_vlan_offload_config(repr, &vlan_offload);
	if (!err) {
		if (on) {
			repr->outer_vlan_info.port_vlan_ena = true;
			repr->outer_vlan_info.vid = pvid;
		} else {
			repr->outer_vlan_info.port_vlan_ena = false;
		}
	}

	return err;
}

static int
ice_dcf_vf_repr_vlan_tpid_set(struct rte_eth_dev *dev,
			      enum rte_vlan_type vlan_type, uint16_t tpid)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	int err = 0;

	if (!ice_dcf_vlan_offload_ena(repr))
		return -ENOTSUP;

	if (vlan_type != RTE_ETH_VLAN_TYPE_OUTER) {
		PMD_DRV_LOG(ERR,
			    "Can accelerate only outer VLAN in QinQ\n");
		return -EINVAL;
	}

	if (tpid != RTE_ETHER_TYPE_QINQ &&
	    tpid != RTE_ETHER_TYPE_VLAN &&
	    tpid != RTE_ETHER_TYPE_QINQ1) {
		PMD_DRV_LOG(ERR,
			    "Invalid TPID: 0x%04x\n", tpid);
		return -EINVAL;
	}

	repr->outer_vlan_info.tpid = tpid;

	if (repr->outer_vlan_info.port_vlan_ena) {
		err = ice_dcf_vf_repr_vlan_pvid_set(dev,
						    repr->outer_vlan_info.vid,
						    true);
		if (err) {
			PMD_DRV_LOG(ERR,
				    "Failed to reset port VLAN : %d\n",
				    err);
			return err;
		}
	}

	if (repr->outer_vlan_info.stripping_ena) {
		err = ice_dcf_vf_repr_vlan_offload_set(dev,
						       RTE_ETH_VLAN_STRIP_MASK);
		if (err) {
			PMD_DRV_LOG(ERR,
				    "Failed to reset VLAN stripping : %d\n",
				    err);
			return err;
		}
	}

	return 0;
}

static int
ice_dcf_repr_query_stats(struct ice_dcf_hw *hw,
			 uint16_t vf_id, struct virtchnl_eth_stats *pstats)
{
	struct virtchnl_queue_select q_stats;
	struct dcf_virtchnl_cmd args;
	int err;

	memset(&q_stats, 0, sizeof(q_stats));
	q_stats.vsi_id = hw->vf_vsi_map[vf_id] & ~VIRTCHNL_DCF_VF_VSI_VALID;

	args.v_op = VIRTCHNL_OP_GET_STATS;
	args.req_msg = (uint8_t *)&q_stats;
	args.req_msglen = sizeof(q_stats);
	args.rsp_msglen = sizeof(struct virtchnl_eth_stats);
	args.rsp_msgbuf = (uint8_t *)pstats;
	args.rsp_buflen = sizeof(struct virtchnl_eth_stats);

	err = ice_dcf_execute_virtchnl_cmd(hw, &args);
	if (err) {
		PMD_DRV_LOG(ERR, "fail to execute command OP_GET_STATS");
		return err;
	}

	return 0;
}

static int
ice_dcf_vf_repr_stats_reset(struct rte_eth_dev *dev)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct ice_dcf_hw *hw = ice_dcf_vf_repr_hw(repr);
	struct virtchnl_eth_stats pstats;
	int ret;

	if (hw->resetting)
		return 0;

	/* read stat values to clear hardware registers */
	ret = ice_dcf_repr_query_stats(hw, repr->vf_id, &pstats);
	if (ret != 0)
		return ret;

	/* set stats offset base on current values */
	hw->eth_stats_offset = pstats;

	return 0;
}

static void
ice_dcf_stat_update_48(uint64_t *offset, uint64_t *stat)
{
	if (*stat >= *offset)
		*stat = *stat - *offset;
	else
		*stat = (uint64_t)((*stat +
			((uint64_t)1 << ICE_DCF_REPR_48_BIT_WIDTH)) - *offset);

	*stat &= ICE_DCF_REPR_48_BIT_MASK;
}

static void
ice_dcf_stat_update_32(uint64_t *offset, uint64_t *stat)
{
	if (*stat >= *offset)
		*stat = (uint64_t)(*stat - *offset);
	else
		*stat = (uint64_t)((*stat +
			((uint64_t)1 << ICE_DCF_REPR_32_BIT_WIDTH)) - *offset);
}

static void
ice_dcf_update_stats(struct ice_dcf_hw *hw, struct virtchnl_eth_stats *nes)
{
	struct virtchnl_eth_stats *oes = &hw->eth_stats_offset;

	ice_dcf_stat_update_48(&oes->rx_bytes, &nes->rx_bytes);
	ice_dcf_stat_update_48(&oes->rx_unicast, &nes->rx_unicast);
	ice_dcf_stat_update_48(&oes->rx_multicast, &nes->rx_multicast);
	ice_dcf_stat_update_48(&oes->rx_broadcast, &nes->rx_broadcast);
	ice_dcf_stat_update_32(&oes->rx_discards, &nes->rx_discards);
	ice_dcf_stat_update_48(&oes->tx_bytes, &nes->tx_bytes);
	ice_dcf_stat_update_48(&oes->tx_unicast, &nes->tx_unicast);
	ice_dcf_stat_update_48(&oes->tx_multicast, &nes->tx_multicast);
	ice_dcf_stat_update_48(&oes->tx_broadcast, &nes->tx_broadcast);
	ice_dcf_stat_update_32(&oes->tx_errors, &nes->tx_errors);
	ice_dcf_stat_update_32(&oes->tx_discards, &nes->tx_discards);
}

static int
ice_dcf_vf_repr_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct ice_dcf_hw *hw = ice_dcf_vf_repr_hw(repr);
	struct virtchnl_eth_stats pstats;
	int ret;

	if (hw->resetting) {
		PMD_DRV_LOG(ERR,
			    "The DCF has been reset by PF, please reinit first");
		return -EIO;
	}

	ret = ice_dcf_repr_query_stats(hw, repr->vf_id, &pstats);
	if (ret == 0) {
		uint8_t crc_stats_len = (dev->data->dev_conf.rxmode.offloads &
					 RTE_ETH_RX_OFFLOAD_KEEP_CRC) ? 0 :
					 RTE_ETHER_CRC_LEN;
		ice_dcf_update_stats(hw, &pstats);
		stats->ipackets = pstats.rx_unicast + pstats.rx_multicast +
				pstats.rx_broadcast - pstats.rx_discards;
		stats->opackets = pstats.tx_broadcast + pstats.tx_multicast +
						pstats.tx_unicast;
		stats->imissed = pstats.rx_discards;
		stats->oerrors = pstats.tx_errors + pstats.tx_discards;
		stats->ibytes = pstats.rx_bytes;
		stats->ibytes -= stats->ipackets * crc_stats_len;
		stats->obytes = pstats.tx_bytes;
	} else {
		PMD_DRV_LOG(ERR, "Get statistics failed, ret:%d", ret);
	}
	return ret;
}
static int
ice_dcf_repr_add_del_eth_addr(struct ice_dcf_hw *hw,
			uint16_t vf_id,
			struct rte_ether_addr *addr,
			bool add, uint8_t type)
{
	struct virtchnl_ether_addr_list *list;
	struct dcf_virtchnl_cmd args;
	uint8_t cmd_buffer[sizeof(struct virtchnl_ether_addr_list) +
			   sizeof(struct virtchnl_ether_addr)];
	int err;

	list = (struct virtchnl_ether_addr_list *)cmd_buffer;
	list->vsi_id = hw->vf_vsi_map[vf_id] & ~VIRTCHNL_DCF_VF_VSI_VALID;
	list->num_elements = 1;
	list->list[0].type = type;
	rte_memcpy(list->list[0].addr, addr->addr_bytes,
	    sizeof(addr->addr_bytes));

	args.v_op = add ? VIRTCHNL_OP_ADD_ETH_ADDR : VIRTCHNL_OP_DEL_ETH_ADDR;
	args.req_msg = cmd_buffer;
	args.req_msglen = sizeof(cmd_buffer);

	err = ice_dcf_execute_virtchnl_cmd(hw, &args);
	if (err) {
		PMD_DRV_LOG(ERR, "Fail to execute command %s",
			    add ? "OP_ADD_ETH_ADDR" :  "OP_DEL_ETH_ADDR");
		return err;
	}

	return 0;
}

static int
ice_dcf_vf_repr_add_mac_addr(struct rte_eth_dev *dev, struct rte_ether_addr *addr,
		     __rte_unused uint32_t index,
		     __rte_unused uint32_t pool)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct ice_dcf_hw *hw = ice_dcf_vf_repr_hw(repr);
	int err;

	if (rte_is_zero_ether_addr(addr)) {
		PMD_DRV_LOG(ERR, "Invalid Ethernet Address");
		return -EINVAL;
	}

	err = ice_dcf_repr_add_del_eth_addr(hw, repr->vf_id, addr, true, VIRTCHNL_ETHER_ADDR_EXTRA);
	if (err) {
		PMD_DRV_LOG(ERR, "fail to add MAC address");
		return -EIO;
	}

	repr->mac_num++;

	return 0;
}

static void
ice_dcf_vf_repr_del_mac_addr(struct rte_eth_dev *dev, uint32_t index)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct ice_dcf_hw *hw = ice_dcf_vf_repr_hw(repr);
	struct rte_ether_addr *addr;
	int err;

	addr = &dev->data->mac_addrs[index];

	err = ice_dcf_repr_add_del_eth_addr(hw, repr->vf_id, addr,
					false, VIRTCHNL_ETHER_ADDR_EXTRA);
	if (err)
		PMD_DRV_LOG(ERR, "fail to del MAC address");

	repr->mac_num--;
}

static int
ice_dcf_add_del_vlan_v2(struct rte_eth_dev *dev, uint16_t vlanid, bool add)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct ice_dcf_hw *hw = ice_dcf_vf_repr_hw(repr);
	struct virtchnl_vlan_filter_list_v2 vlan_filter;
	struct dcf_virtchnl_cmd args;
	struct virtchnl_vlan *vlan_setting;
	int err;

	vlan_setting = &vlan_filter.filters[0].outer;
	memset(&vlan_filter, 0, sizeof(vlan_filter));
	vlan_filter.vport_id = hw->vf_vsi_map[repr->vf_id] & ~VIRTCHNL_DCF_VF_VSI_VALID;
	vlan_filter.num_elements = 1;
	vlan_setting->tpid = RTE_ETHER_TYPE_VLAN;
	vlan_setting->tci = vlanid;

	memset(&args, 0, sizeof(args));
	args.v_op = add ? VIRTCHNL_OP_ADD_VLAN_V2 : VIRTCHNL_OP_DEL_VLAN_V2;
	args.req_msg = (uint8_t *)&vlan_filter;
	args.req_msglen = sizeof(vlan_filter);

	err = ice_dcf_execute_virtchnl_cmd(hw, &args);
	if (err) {
		PMD_DRV_LOG(ERR, "Fail to execute command %s",
				add ? "OP_ADD_ETH_ADDR" :  "OP_DEL_ETH_ADDR");
		return err;
	}
	return 0;
}

static int
ice_dcf_vf_repr_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	int err;

	if (!ice_dcf_vlan_offload_ena(repr)) {
		PMD_DRV_LOG(ERR, "It is not VLAN_V2");
		return -ENOTSUP;
	}

	err = ice_dcf_add_del_vlan_v2(dev, vlan_id, on);
	if (err) {
		PMD_DRV_LOG(ERR, "Failed to set vlan filter, err:%d", err);
		return -ENOTSUP;
	}
	return 0;
}

static const struct eth_dev_ops ice_dcf_vf_repr_dev_ops = {
	.dev_configure        = ice_dcf_vf_repr_dev_configure,
	.dev_start            = ice_dcf_vf_repr_dev_start,
	.dev_stop             = ice_dcf_vf_repr_dev_stop,
	.dev_close            = ice_dcf_vf_repr_dev_close,
	.dev_infos_get        = ice_dcf_vf_repr_dev_info_get,
	.rx_queue_setup       = ice_dcf_vf_repr_rx_queue_setup,
	.tx_queue_setup       = ice_dcf_vf_repr_tx_queue_setup,
	.promiscuous_enable   = ice_dcf_vf_repr_promiscuous_enable,
	.promiscuous_disable  = ice_dcf_vf_repr_promiscuous_disable,
	.allmulticast_enable  = ice_dcf_vf_repr_allmulticast_enable,
	.allmulticast_disable = ice_dcf_vf_repr_allmulticast_disable,
	.link_update          = ice_dcf_vf_repr_link_update,
	.vlan_offload_set     = ice_dcf_vf_repr_vlan_offload_set,
	.vlan_pvid_set        = ice_dcf_vf_repr_vlan_pvid_set,
	.vlan_tpid_set        = ice_dcf_vf_repr_vlan_tpid_set,
	.stats_reset          = ice_dcf_vf_repr_stats_reset,
	.stats_get            = ice_dcf_vf_repr_stats_get,
	.mac_addr_add         = ice_dcf_vf_repr_add_mac_addr,
	.mac_addr_remove      = ice_dcf_vf_repr_del_mac_addr,
	.vlan_filter_set      = ice_dcf_vf_repr_vlan_filter_set,
};

int
ice_dcf_vf_repr_init(struct rte_eth_dev *vf_rep_eth_dev, void *init_param)
{
	struct ice_dcf_vf_repr *repr = vf_rep_eth_dev->data->dev_private;
	struct ice_dcf_vf_repr_param *param = init_param;

	repr->dcf_eth_dev = param->dcf_eth_dev;
	repr->switch_domain_id = param->switch_domain_id;
	repr->vf_id = param->vf_id;
	repr->outer_vlan_info.port_vlan_ena = false;
	repr->outer_vlan_info.stripping_ena = false;
	repr->outer_vlan_info.tpid = RTE_ETHER_TYPE_VLAN;
	repr->mac_num = 1;

	vf_rep_eth_dev->dev_ops = &ice_dcf_vf_repr_dev_ops;

	vf_rep_eth_dev->rx_pkt_burst = ice_dcf_vf_repr_rx_burst;
	vf_rep_eth_dev->tx_pkt_burst = ice_dcf_vf_repr_tx_burst;

	vf_rep_eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
	vf_rep_eth_dev->data->representor_id = repr->vf_id;
	vf_rep_eth_dev->data->backer_port_id = repr->dcf_eth_dev->data->port_id;

	vf_rep_eth_dev->data->mac_addrs = &repr->mac_addr;

	rte_eth_random_addr(repr->mac_addr.addr_bytes);

	return 0;
}

int
ice_dcf_vf_repr_uninit(struct rte_eth_dev *vf_rep_eth_dev)
{
	vf_rep_eth_dev->data->mac_addrs = NULL;

	return 0;
}

int
ice_dcf_vf_repr_init_vlan(struct rte_eth_dev *vf_rep_eth_dev)
{
	struct ice_dcf_vf_repr *repr = vf_rep_eth_dev->data->dev_private;
	int err;

	err = ice_dcf_vf_repr_vlan_offload_set(vf_rep_eth_dev,
					       RTE_ETH_VLAN_STRIP_MASK);
	if (err) {
		PMD_DRV_LOG(ERR, "Failed to set VLAN offload");
		return err;
	}

	if (repr->outer_vlan_info.port_vlan_ena) {
		err = ice_dcf_vf_repr_vlan_pvid_set(vf_rep_eth_dev,
						    repr->outer_vlan_info.vid,
						    true);
		if (err) {
			PMD_DRV_LOG(ERR, "Failed to enable port VLAN");
			return err;
		}
	}

	return 0;
}

void
ice_dcf_vf_repr_stop_all(struct ice_dcf_adapter *dcf_adapter)
{
	uint16_t vf_id;
	int ret;

	if (!dcf_adapter->repr_infos)
		return;

	for (vf_id = 0; vf_id < dcf_adapter->real_hw.num_vfs; vf_id++) {
		struct rte_eth_dev *vf_rep_eth_dev =
				dcf_adapter->repr_infos[vf_id].vf_rep_eth_dev;
		if (!vf_rep_eth_dev || vf_rep_eth_dev->data->dev_started == 0)
			continue;

		ret = ice_dcf_vf_repr_dev_stop(vf_rep_eth_dev);
		if (!ret)
			vf_rep_eth_dev->data->dev_started = 0;
	}
}
