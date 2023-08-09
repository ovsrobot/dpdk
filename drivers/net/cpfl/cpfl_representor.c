/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include "cpfl_representor.h"
#include "cpfl_rxtx.h"

static int
cpfl_repr_whitelist_update(struct cpfl_adapter_ext *adapter,
			   struct cpfl_repr_id *repr_id,
			   struct rte_eth_dev *dev)
{
	int ret;

	if (rte_hash_lookup(adapter->repr_whitelist_hash, repr_id) < 0)
		return -ENOENT;

	ret = rte_hash_add_key_data(adapter->repr_whitelist_hash, repr_id, dev);

	return ret;
}

static int
cpfl_repr_whitelist_add(struct cpfl_adapter_ext *adapter,
			struct cpfl_repr_id *repr_id)
{
	int ret;

	rte_spinlock_lock(&adapter->repr_lock);
	if (rte_hash_lookup(adapter->repr_whitelist_hash, repr_id) >= 0) {
		ret = -EEXIST;
		goto err;
	}

	ret = rte_hash_add_key(adapter->repr_whitelist_hash, repr_id);
	if (ret < 0)
		goto err;

	rte_spinlock_unlock(&adapter->repr_lock);
	return 0;
err:
	rte_spinlock_unlock(&adapter->repr_lock);
	return ret;
}

static int
cpfl_repr_devargs_process_one(struct cpfl_adapter_ext *adapter,
			      struct rte_eth_devargs *eth_da)
{
	struct cpfl_repr_id repr_id;
	int ret, c, p, v;

	for (c = 0; c < eth_da->nb_mh_controllers; c++) {
		for (p = 0; p < eth_da->nb_ports; p++) {
			repr_id.type = eth_da->type;
			if (eth_da->type == RTE_ETH_REPRESENTOR_PF) {
				repr_id.host_id = eth_da->mh_controllers[c];
				repr_id.pf_id = eth_da->ports[p];
				repr_id.vf_id = 0;
				ret = cpfl_repr_whitelist_add(adapter, &repr_id);
				if (ret == -EEXIST)
					continue;
				if (ret) {
					PMD_DRV_LOG(ERR, "Failed to add PF repr to whitelist, "
							 "host_id = %d, pf_id = %d.",
						    repr_id.host_id, repr_id.pf_id);
					return ret;
				}
			} else if (eth_da->type == RTE_ETH_REPRESENTOR_VF) {
				for (v = 0; v < eth_da->nb_representor_ports; v++) {
					repr_id.host_id = eth_da->mh_controllers[c];
					repr_id.pf_id = eth_da->ports[p];
					repr_id.vf_id = eth_da->representor_ports[v];
					ret = cpfl_repr_whitelist_add(adapter, &repr_id);
					if (ret == -EEXIST)
						continue;
					if (ret) {
						PMD_DRV_LOG(ERR, "Failed to add VF repr to whitelist, "
								 "host_id = %d, pf_id = %d, vf_id = %d.",
							    repr_id.host_id,
							    repr_id.pf_id,
							    repr_id.vf_id);
						return ret;
					}
				}
			}
		}
	}

	return 0;
}

int
cpfl_repr_devargs_process(struct cpfl_adapter_ext *adapter)
{
	struct cpfl_devargs *devargs = &adapter->devargs;
	int ret, i, j;

	/* check and refine repr args */
	for (i = 0; i < devargs->repr_args_num; i++) {
		struct rte_eth_devargs *eth_da = &devargs->repr_args[i];

		/* set default host_id to xeon host */
		if (eth_da->nb_mh_controllers == 0) {
			eth_da->nb_mh_controllers = 1;
			eth_da->mh_controllers[0] = CPFL_HOST_ID_HOST;
		} else {
			for (j = 0; j < eth_da->nb_mh_controllers; j++) {
				if (eth_da->mh_controllers[j] > CPFL_HOST_ID_ACC) {
					PMD_INIT_LOG(ERR, "Invalid Host ID %d",
						     eth_da->mh_controllers[j]);
					return -EINVAL;
				}
			}
		}

		/* set default pf to APF */
		if (eth_da->nb_ports == 0) {
			eth_da->nb_ports = 1;
			eth_da->ports[0] = CPFL_PF_TYPE_APF;
		} else {
			for (j = 0; j < eth_da->nb_ports; j++) {
				if (eth_da->ports[j] > CPFL_PF_TYPE_CPF) {
					PMD_INIT_LOG(ERR, "Invalid Host ID %d",
						     eth_da->ports[j]);
					return -EINVAL;
				}
			}
		}

		ret = cpfl_repr_devargs_process_one(adapter, eth_da);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_repr_whitelist_del(struct cpfl_adapter_ext *adapter,
			struct cpfl_repr_id *repr_id)
{
	int ret;

	rte_spinlock_lock(&adapter->repr_lock);

	ret = rte_hash_del_key(adapter->repr_whitelist_hash, repr_id);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "Failed to delete repr from whitelist."
				 "host_id = %d, type = %d, pf_id = %d, vf_id = %d",
				 repr_id->host_id, repr_id->type,
				 repr_id->pf_id, repr_id->vf_id);
		goto err;
	}

	rte_spinlock_unlock(&adapter->repr_lock);
	return 0;
err:
	rte_spinlock_unlock(&adapter->repr_lock);
	return ret;
}

static int
cpfl_repr_uninit(struct rte_eth_dev *eth_dev)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(eth_dev);
	struct cpfl_adapter_ext *adapter = repr->itf.adapter;

	eth_dev->data->mac_addrs = NULL;

	cpfl_repr_whitelist_del(adapter, &repr->repr_id);

	return 0;
}

static int
cpfl_repr_dev_configure(struct rte_eth_dev *dev)
{
	/* now only 1 RX queue is supported */
	if (dev->data->nb_rx_queues > 1)
		return -EINVAL;

	return 0;
}

static int
cpfl_repr_dev_close(struct rte_eth_dev *dev)
{
	return cpfl_repr_uninit(dev);
}

static int
cpfl_repr_dev_info_get(struct rte_eth_dev *ethdev,
		       struct rte_eth_dev_info *dev_info)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(ethdev);

	dev_info->device = ethdev->device;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;
	dev_info->min_rx_bufsize = CPFL_MIN_BUF_SIZE;
	dev_info->max_rx_pktlen = CPFL_MAX_FRAME_SIZE;

	dev_info->flow_type_rss_offloads = CPFL_RSS_OFFLOAD_ALL;

	dev_info->rx_offload_capa =
		RTE_ETH_RX_OFFLOAD_VLAN_STRIP		|
		RTE_ETH_RX_OFFLOAD_QINQ_STRIP		|
		RTE_ETH_RX_OFFLOAD_IPV4_CKSUM		|
		RTE_ETH_RX_OFFLOAD_UDP_CKSUM		|
		RTE_ETH_RX_OFFLOAD_TCP_CKSUM		|
		RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM	|
		RTE_ETH_RX_OFFLOAD_SCATTER		|
		RTE_ETH_RX_OFFLOAD_VLAN_FILTER		|
		RTE_ETH_RX_OFFLOAD_RSS_HASH		|
		RTE_ETH_RX_OFFLOAD_TIMESTAMP;

	dev_info->tx_offload_capa =
		RTE_ETH_TX_OFFLOAD_VLAN_INSERT		|
		RTE_ETH_TX_OFFLOAD_QINQ_INSERT		|
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM		|
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM	|
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS		|
		RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_free_thresh = CPFL_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_free_thresh = CPFL_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = CPFL_DEFAULT_TX_RS_THRESH,
		.offloads = 0,
	};

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = CPFL_MAX_RING_DESC,
		.nb_min = CPFL_MIN_RING_DESC,
		.nb_align = CPFL_ALIGN_RING_DESC,
	};

	dev_info->tx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = CPFL_MAX_RING_DESC,
		.nb_min = CPFL_MIN_RING_DESC,
		.nb_align = CPFL_ALIGN_RING_DESC,
	};

	dev_info->switch_info.name = ethdev->device->name;
	dev_info->switch_info.domain_id = 0; /* the same domain*/
	dev_info->switch_info.port_id = repr->vport_info->vport_info.vsi_id;

	return 0;
}

static int
cpfl_repr_dev_start(struct rte_eth_dev *dev)
{
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

static int
cpfl_repr_dev_stop(struct rte_eth_dev *dev)
{
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	dev->data->dev_started = 0;
	return 0;
}

static int
cpfl_repr_rx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_id,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 __rte_unused const struct rte_eth_rxconf *conf,
			 struct rte_mempool *pool)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(dev);
	struct cpfl_repr_rx_queue *rxq;
	char ring_name[RTE_RING_NAMESIZE];
	struct rte_ring *rx_ring;

	if (!(dev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR)) {
		PMD_INIT_LOG(ERR, "This ethdev is not representor.");
		return -EINVAL;
	}

	if (!RTE_IS_POWER_OF_2(nb_desc) ||
	    nb_desc > CPFL_MAX_RING_DESC ||
	    nb_desc < CPFL_MIN_RING_DESC) {
		PMD_INIT_LOG(ERR, "nb_desc should < %u, > %u and power of 2)",
			     CPFL_MAX_RING_DESC, CPFL_MIN_RING_DESC);
		return -EINVAL;
	}

	/* Free memory if needed */
	rxq = dev->data->rx_queues[queue_id];
	if (rxq) {
		rte_ring_free(rxq->rx_ring);
		rte_free(rxq);
		dev->data->rx_queues[queue_id] = NULL;
	}

	/* Allocate rx queue data structure */
	rxq = rte_zmalloc_socket("cpfl representor rx queue",
				 sizeof(struct cpfl_repr_rx_queue),
				 RTE_CACHE_LINE_SIZE,
				 socket_id);
	if (!rxq) {
		PMD_INIT_LOG(ERR, "Failed to allocate memory for representor rx queue");
		return -ENOMEM;
	}

	/* use rte_ring as rx queue of representor */
	if (repr->repr_id.type == RTE_ETH_REPRESENTOR_VF)
		snprintf(ring_name, sizeof(ring_name), "cpfl_repr_c%dpf%dvf%d_rx",
			 repr->repr_id.host_id, repr->repr_id.pf_id, repr->repr_id.vf_id);
	else
		snprintf(ring_name, sizeof(ring_name), "cpfl_repr_c%dpf%d_rx",
			 repr->repr_id.host_id, repr->repr_id.pf_id);
	rx_ring = rte_ring_lookup(ring_name);
	if (rx_ring) {
		PMD_INIT_LOG(ERR, "rte_ring %s is occuriped.", ring_name);
		rte_free(rxq);
		return -EEXIST;
	}

	rx_ring = rte_ring_create(ring_name, nb_desc, socket_id,
				  RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (!rx_ring) {
		PMD_INIT_LOG(ERR, "Failed to create ring %s.", ring_name);
		rte_free(rxq);
		return -EINVAL;
	}

	rxq->mb_pool = pool;
	rxq->repr = repr;
	rxq->rx_ring = rx_ring;
	dev->data->rx_queues[queue_id] = rxq;

	return 0;
}

static int
cpfl_repr_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_id,
			 __rte_unused uint16_t nb_desc,
			 unsigned int socket_id,
			 __rte_unused const struct rte_eth_txconf *conf)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(dev);
	struct cpfl_adapter_ext *adapter = repr->itf.adapter;
	struct cpfl_repr_tx_queue *txq;
	struct cpfl_vport *vport;

	if (!(dev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR)) {
		PMD_INIT_LOG(ERR, "This ethdev is not representor.");
		return -EINVAL;
	}

	txq = dev->data->tx_queues[queue_id];
	if (txq) {
		rte_free(txq);
		dev->data->rx_queues[queue_id] = NULL;
	}
	txq = rte_zmalloc_socket("cpfl representor tx queue",
				 sizeof(struct cpfl_repr_tx_queue),
				 RTE_CACHE_LINE_SIZE,
				 socket_id);
	if (!txq) {
		PMD_INIT_LOG(ERR, "Failed to allocate memory for representor tx queue");
		return -ENOMEM;
	}
	/* use vport HW queue to transmit, no need to allocate
	 * a ring for it
	 */
	txq->repr = repr;
	dev->data->tx_queues[queue_id] = txq;

	vport = adapter->exceptional_vport;
	if (!vport) {
		PMD_INIT_LOG(ERR, "No default vport is created for exceptianl path");
		return -ENODEV;
	}
	/* TODO: need to select the hw txq when multi txqs are there.
	 * Now just use the default queue 0
	 */
	txq->txq = ((struct rte_eth_dev_data *)vport->itf.data)->tx_queues[0];

	return 0;
}

static int
cpfl_repr_link_update(struct rte_eth_dev *ethdev,
		      __rte_unused int wait_to_complete)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(ethdev);
	struct rte_eth_link *dev_link = &ethdev->data->dev_link;

	if (!(ethdev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR)) {
		PMD_INIT_LOG(ERR, "This ethdev is not representor.");
		return -EINVAL;
	}
	dev_link->link_status = repr->func_up ?
			RTE_ETH_LINK_UP : RTE_ETH_LINK_DOWN;

	return 0;
}

static const struct eth_dev_ops cpfl_repr_dev_ops = {
	.dev_start		= cpfl_repr_dev_start,
	.dev_stop		= cpfl_repr_dev_stop,
	.dev_configure		= cpfl_repr_dev_configure,
	.dev_close		= cpfl_repr_dev_close,
	.dev_infos_get		= cpfl_repr_dev_info_get,

	.rx_queue_setup		= cpfl_repr_rx_queue_setup,
	.tx_queue_setup		= cpfl_repr_tx_queue_setup,
	.link_update		= cpfl_repr_link_update,
};

static int
cpfl_repr_init(struct rte_eth_dev *eth_dev, void *init_param)
{
	struct cpfl_repr *repr = CPFL_DEV_TO_REPR(eth_dev);
	struct cpfl_repr_param *param = init_param;
	struct cpfl_adapter_ext *adapter = param->adapter;

	repr->repr_id = param->repr_id;
	repr->vport_info = param->vport_info;
	repr->itf.type = CPFL_ITF_TYPE_REPRESENTOR;
	repr->itf.adapter = adapter;
	repr->itf.data = eth_dev->data;
	if (repr->vport_info->vport_info.vport_status == CPCHNL2_VPORT_STATUS_ENABLED)
		repr->func_up = true;

	eth_dev->dev_ops = &cpfl_repr_dev_ops;

	eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
	/* bit[15:14] type
	 * bit[13] xeon/acc
	 * bit[12] apf/cpf
	 * bit[11:0] vf
	 */
	eth_dev->data->representor_id =
		(uint16_t)(repr->repr_id.type << 14 |
			   repr->repr_id.host_id << 13 |
			   repr->repr_id.pf_id << 12 |
			   repr->repr_id.vf_id);

	eth_dev->data->mac_addrs = &repr->mac_addr;

	rte_eth_random_addr(repr->mac_addr.addr_bytes);

	return cpfl_repr_whitelist_update(adapter, &repr->repr_id, eth_dev);
}

static int
cpfl_func_id_get(uint8_t host_id, uint8_t pf_id)
{
	if ((host_id != CPFL_HOST_ID_HOST &&
	     host_id != CPFL_HOST_ID_ACC) ||
	    (pf_id != CPFL_PF_TYPE_APF &&
	     pf_id != CPFL_PF_TYPE_CPF))
		return -EINVAL;

	static const uint32_t func_id_map[CPFL_HOST_ID_NUM][CPFL_PF_TYPE_NUM] = {
		[CPFL_HOST_ID_HOST][CPFL_PF_TYPE_APF] = HOST0_APF,
		[CPFL_HOST_ID_HOST][CPFL_PF_TYPE_CPF] = HOST0_CPF_ID,
		[CPFL_HOST_ID_ACC][CPFL_PF_TYPE_APF] = ACC_APF_ID,
		[CPFL_HOST_ID_ACC][CPFL_PF_TYPE_CPF] = ACC_CPF_ID,
	};

	return func_id_map[host_id][pf_id];
}

static bool
match_repr_with_vport(const struct cpfl_repr_id *repr_id,
		      struct cpchnl2_vport_info *info)
{
	int func_id;

	if (repr_id->type == RTE_ETH_REPRESENTOR_PF &&
	    info->func_type == 0) {
		func_id = cpfl_func_id_get(repr_id->host_id, repr_id->pf_id);
		if (func_id < 0)
			return false;
		else
			return true;
	} else if (repr_id->type == RTE_ETH_REPRESENTOR_VF &&
		   info->func_type == 1) {
		if (repr_id->vf_id == info->vf_id)
			return true;
	}

	return false;
}

static int
cpfl_repr_vport_list_query(struct cpfl_adapter_ext *adapter,
			   const struct cpfl_repr_id *repr_id,
			   struct cpchnl2_get_vport_list_response *response)
{
	struct cpfl_vport_id vi;
	int ret;

	if (repr_id->type == RTE_ETH_REPRESENTOR_PF) {
		/* PF */
		vi.func_type = CPCHNL2_FUNC_TYPE_PF;
		vi.pf_id = cpfl_func_id_get(repr_id->host_id, repr_id->pf_id);
		vi.vf_id = 0;
	} else {
		/* VF */
		vi.func_type = CPCHNL2_FUNC_TYPE_SRIOV;
		vi.pf_id = HOST0_APF;
		vi.vf_id = repr_id->vf_id;
	}

	ret = cpfl_cc_vport_list_get(adapter, &vi, response);

	return ret;
}

static int
cpfl_repr_vport_info_query(struct cpfl_adapter_ext *adapter,
			   const struct cpfl_repr_id *repr_id,
			   struct cpchnl2_vport_id *vport_id,
			   struct cpchnl2_get_vport_info_response *response)
{
	struct cpfl_vport_id vi;
	int ret;

	if (repr_id->type == RTE_ETH_REPRESENTOR_PF) {
		/* PF */
		vi.func_type = CPCHNL2_FUNC_TYPE_PF;
		vi.pf_id = cpfl_func_id_get(repr_id->host_id, repr_id->pf_id);
		vi.vf_id = 0;
	} else {
		/* VF */
		vi.func_type = CPCHNL2_FUNC_TYPE_SRIOV;
		vi.pf_id = HOST0_APF;
		vi.vf_id = repr_id->vf_id;
	}

	ret = cpfl_cc_vport_info_get(adapter, vport_id, &vi, response);

	return ret;
}

static int
cpfl_repr_vport_map_update(struct cpfl_adapter_ext *adapter,
			   const struct cpfl_repr_id *repr_id, uint32_t vport_id,
			   struct cpchnl2_get_vport_info_response *response)
{
	struct cpfl_vport_id vi;
	int ret;

	vi.vport_id = vport_id;
	if (repr_id->type == RTE_ETH_REPRESENTOR_PF) {
		/* PF */
		vi.func_type = CPCHNL2_FUNC_TYPE_PF;
		vi.pf_id = cpfl_func_id_get(repr_id->host_id, repr_id->pf_id);
	} else {
		/* VF */
		vi.func_type = CPCHNL2_FUNC_TYPE_SRIOV;
		vi.pf_id = HOST0_APF;
		vi.vf_id = repr_id->vf_id;
	}

	ret = cpfl_vport_info_create(adapter, &vi, &response->info);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Fail to update vport map hash for representor.");
		return ret;
	}

	return 0;
}

int
cpfl_repr_create(struct rte_pci_device *pci_dev, struct cpfl_adapter_ext *adapter)
{
	struct rte_eth_dev *dev;
	uint32_t iter = 0;
	const struct cpfl_repr_id *repr_id;
	const struct cpfl_vport_id *vp_id;
	struct cpchnl2_get_vport_list_response *vlist_resp;
	struct cpchnl2_get_vport_info_response vinfo_resp;
	int ret;

	vlist_resp = rte_zmalloc(NULL, IDPF_DFLT_MBX_BUF_SIZE, 0);
	if (vlist_resp == NULL)
		return -ENOMEM;

	rte_spinlock_lock(&adapter->repr_lock);

	while (rte_hash_iterate(adapter->repr_whitelist_hash,
				(const void **)&repr_id, (void **)&dev, &iter) >= 0) {
		struct cpfl_vport_info *vi;
		char name[RTE_ETH_NAME_MAX_LEN];
		uint32_t iter_iter = 0;
		bool matched;
		int i;

		/* skip representor already be created */
		if (dev != NULL)
			continue;

		if (repr_id->type == RTE_ETH_REPRESENTOR_VF)
			snprintf(name, sizeof(name), "net_%s_representor_c%dpf%dvf%d",
				 pci_dev->name,
				 repr_id->host_id,
				 repr_id->pf_id,
				 repr_id->vf_id);
		else
			snprintf(name, sizeof(name), "net_%s_representor_c%dpf%d",
				 pci_dev->name,
				 repr_id->host_id,
				 repr_id->pf_id);

		/* get vport list for the port representor */
		ret = cpfl_repr_vport_list_query(adapter, repr_id, vlist_resp);
		if (ret != 0) {
			PMD_INIT_LOG(ERR, "Failed to get host%d pf%d vf%d's vport list",
				     repr_id->host_id, repr_id->pf_id, repr_id->vf_id);
			rte_spinlock_unlock(&adapter->repr_lock);
			rte_free(vlist_resp);
			return ret;
		}

		/* get all vport info for the port representor */
		for (i = 0; i < vlist_resp->nof_vports; i++) {
			ret = cpfl_repr_vport_info_query(adapter, repr_id,
							 &vlist_resp->vports[i], &vinfo_resp);
			if (ret != 0) {
				PMD_INIT_LOG(ERR, "Failed to get host%d pf%d vf%d vport[%d]'s info",
					     repr_id->host_id, repr_id->pf_id, repr_id->vf_id,
					     vlist_resp->vports[i].vport_id);
				rte_spinlock_unlock(&adapter->repr_lock);
				rte_free(vlist_resp);
				return ret;
			}

			ret = cpfl_repr_vport_map_update(adapter, repr_id,
						 vlist_resp->vports[i].vport_id, &vinfo_resp);
			if (ret != 0) {
				PMD_INIT_LOG(ERR, "Failed to update  host%d pf%d vf%d vport[%d]'s info to vport_map_hash",
					     repr_id->host_id, repr_id->pf_id, repr_id->vf_id,
					     vlist_resp->vports[i].vport_id);
				rte_spinlock_unlock(&adapter->repr_lock);
				rte_free(vlist_resp);
				return ret;
			}
		}

		/* find a matched vport */
		rte_spinlock_lock(&adapter->vport_map_lock);

		matched = false;
		while (rte_hash_iterate(adapter->vport_map_hash,
					(const void **)&vp_id, (void **)&vi, &iter_iter) >= 0) {
			struct cpfl_repr_param param;

			if (!match_repr_with_vport(repr_id, &vi->vport_info))
				continue;

			matched = true;

			param.adapter = adapter;
			param.repr_id = *repr_id;
			param.vport_info = vi;

			ret = rte_eth_dev_create(&pci_dev->device,
						 name,
						 sizeof(struct cpfl_repr),
						 NULL, NULL, cpfl_repr_init,
						 &param);
			if (ret != 0) {
				PMD_INIT_LOG(ERR, "Failed to create representor %s", name);
				rte_spinlock_unlock(&adapter->vport_map_lock);
				rte_spinlock_unlock(&adapter->repr_lock);
				rte_free(vlist_resp);
				return ret;
			}
			break;
		}

		/* warning if no match vport detected */
		if (!matched)
			PMD_INIT_LOG(WARNING, "No matched vport for representor %s "
					      "creation will be deferred when vport is detected",
					      name);

		rte_spinlock_unlock(&adapter->vport_map_lock);
	}

	rte_spinlock_unlock(&adapter->repr_lock);
	rte_free(vlist_resp);

	return 0;
}
