/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <errno.h>
#include <sys/types.h>

#include <rte_ethdev.h>

#include "ice_dcf_ethdev.h"
#include "ice_rxtx.h"

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
ice_dcf_vf_repr_dev_configure(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

static int
ice_dcf_vf_repr_dev_start(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = ETH_LINK_UP;

	return 0;
}

static int
ice_dcf_vf_repr_dev_stop(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = ETH_LINK_DOWN;

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

static int
ice_dcf_vf_repr_dev_info_get(struct rte_eth_dev *dev,
			     struct rte_eth_dev_info *dev_info)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct ice_dcf_hw *dcf_hw =
				&repr->dcf_adapter->real_hw;

	dev_info->device = dev->device;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_queues = dcf_hw->vsi_res->num_queue_pairs;
	dev_info->max_tx_queues = dcf_hw->vsi_res->num_queue_pairs;
	dev_info->min_rx_bufsize = ICE_BUF_SIZE_MIN;
	dev_info->max_rx_pktlen = ICE_FRAME_SIZE_MAX;
	dev_info->hash_key_size = dcf_hw->vf_res->rss_key_size;
	dev_info->reta_size = dcf_hw->vf_res->rss_lut_size;
	dev_info->flow_type_rss_offloads = ICE_RSS_OFFLOAD_ALL;

	dev_info->rx_offload_capa =
		DEV_RX_OFFLOAD_VLAN_STRIP |
		DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM |
		DEV_RX_OFFLOAD_TCP_CKSUM |
		DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM |
		DEV_RX_OFFLOAD_SCATTER |
		DEV_RX_OFFLOAD_JUMBO_FRAME |
		DEV_RX_OFFLOAD_VLAN_FILTER |
		DEV_RX_OFFLOAD_VLAN_EXTEND |
		DEV_RX_OFFLOAD_RSS_HASH;
	dev_info->tx_offload_capa =
		DEV_TX_OFFLOAD_VLAN_INSERT |
		DEV_TX_OFFLOAD_IPV4_CKSUM |
		DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM |
		DEV_TX_OFFLOAD_SCTP_CKSUM |
		DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
		DEV_TX_OFFLOAD_TCP_TSO |
		DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
		DEV_TX_OFFLOAD_GRE_TNL_TSO |
		DEV_TX_OFFLOAD_IPIP_TNL_TSO |
		DEV_TX_OFFLOAD_GENEVE_TNL_TSO |
		DEV_TX_OFFLOAD_MULTI_SEGS;

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

static int
ice_dcf_vlan_offload_config(struct ice_dcf_vf_repr *repr,
			    struct virtchnl_dcf_vlan_offload *vlan_offload)
{
	struct dcf_virtchnl_cmd args;

	memset(&args, 0, sizeof(args));
	args.v_op = VIRTCHNL_OP_DCF_VLAN_OFFLOAD;
	args.req_msg = (uint8_t *)vlan_offload;
	args.req_msglen = sizeof(*vlan_offload);

	return ice_dcf_execute_virtchnl_cmd(&repr->dcf_adapter->real_hw, &args);
}

static __rte_always_inline bool
ice_dcf_vlan_offload_ena(struct ice_dcf_vf_repr *repr)
{
	return !!(repr->dcf_adapter->real_hw.vf_res->vf_cap_flags &
		  VIRTCHNL_VF_OFFLOAD_VLAN_V2);
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

	memset(&vlan_offload, 0, sizeof(vlan_offload));

	vlan_offload.vf_id = repr->vf_id;
	vlan_offload.tpid = repr->outer_vlan_tpid;
	vlan_offload.vlan_flags = (VIRTCHNL_DCF_VLAN_TYPE_OUTER <<
				   VIRTCHNL_DCF_VLAN_TYPE_S) |
				  (VIRTCHNL_DCF_VLAN_INSERT_PORT_BASED <<
				   VIRTCHNL_DCF_VLAN_INSERT_MODE_S);
	vlan_offload.vlan_id = on ? pvid : 0;

	err = ice_dcf_vlan_offload_config(repr, &vlan_offload);
	if (!err) {
		repr->pvid = vlan_offload.vlan_id;
		repr->hw_vlan_insert_pvid = on ? 1 : 0;
	}

	return err;
}

static int
ice_dcf_vf_repr_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;
	struct rte_eth_rxmode *rxmode;

	if (!ice_dcf_vlan_offload_ena(repr))
		return -ENOTSUP;

	rxmode = &dev->data->dev_conf.rxmode;

	if (mask & ETH_VLAN_EXTEND_MASK) {
		if (!(rxmode->offloads & DEV_RX_OFFLOAD_VLAN_EXTEND))
			ice_dcf_vf_repr_vlan_pvid_set(dev, 0, 0);
	}

	return 0;
}

static int
ice_dcf_vf_repr_vlan_tpid_set(struct rte_eth_dev *dev,
			      enum rte_vlan_type vlan_type, uint16_t tpid)
{
	struct ice_dcf_vf_repr *repr = dev->data->dev_private;

	if (!ice_dcf_vlan_offload_ena(repr))
		return -ENOTSUP;

	if (vlan_type != ETH_VLAN_TYPE_INNER &&
	    vlan_type != ETH_VLAN_TYPE_OUTER) {
		PMD_DRV_LOG(ERR, "Unsupported vlan type %d", vlan_type);
		return -EINVAL;
	}

	if (vlan_type == ETH_VLAN_TYPE_INNER) {
		PMD_DRV_LOG(ERR,
			    "Can accelerate only outer VLAN in QinQ\n");
		return -EINVAL;
	}

	if (!(dev->data->dev_conf.rxmode.offloads &
	      DEV_RX_OFFLOAD_VLAN_EXTEND)) {
		PMD_DRV_LOG(ERR,
			    "QinQ not enabled.");
		return -EINVAL;
	}

	if (tpid != RTE_ETHER_TYPE_QINQ ||
	    tpid != RTE_ETHER_TYPE_VLAN ||
	    tpid != RTE_ETHER_TYPE_QINQ1) {
		PMD_DRV_LOG(ERR,
			    "Invalid TPID: 0x%04x\n", tpid);
		return -EINVAL;
	}

	repr->outer_vlan_tpid = tpid;

	return ice_dcf_vf_repr_vlan_pvid_set(dev,
					     repr->pvid,
					     repr->hw_vlan_insert_pvid);
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
};

int
ice_dcf_vf_repr_init(struct rte_eth_dev *ethdev, void *init_param)
{
	struct ice_dcf_vf_repr *repr = ethdev->data->dev_private;
	struct ice_dcf_vf_repr_param *param = init_param;

	repr->dcf_adapter = param->adapter;
	repr->switch_domain_id = param->switch_domain_id;
	repr->vf_id = param->vf_id;
	repr->outer_vlan_tpid = RTE_ETHER_TYPE_VLAN;

	ethdev->dev_ops = &ice_dcf_vf_repr_dev_ops;

	ethdev->rx_pkt_burst = ice_dcf_vf_repr_rx_burst;
	ethdev->tx_pkt_burst = ice_dcf_vf_repr_tx_burst;

	ethdev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
	ethdev->data->representor_id = repr->vf_id;

	ethdev->data->mac_addrs = &repr->mac_addr;

	rte_eth_random_addr(repr->mac_addr.addr_bytes);

	return 0;
}

int
ice_dcf_vf_repr_uninit(struct rte_eth_dev *ethdev)
{
	ethdev->data->mac_addrs = NULL;

	return 0;
}
