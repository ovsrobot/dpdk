/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <rte_atomic.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_dev.h>

#include "idpf_ethdev.h"
#include "idpf_rxtx.h"

#define IDPF_TX_SINGLE_Q	"tx_single"
#define IDPF_RX_SINGLE_Q	"rx_single"
#define REPRESENTOR		"representor"

struct idpf_adapter *adapter;
uint16_t used_vecs_num;

static const char * const idpf_valid_args[] = {
	IDPF_TX_SINGLE_Q,
	IDPF_RX_SINGLE_Q,
	REPRESENTOR,
	NULL
};

static int idpf_dev_configure(struct rte_eth_dev *dev);
static int idpf_dev_start(struct rte_eth_dev *dev);
static int idpf_dev_stop(struct rte_eth_dev *dev);
static int idpf_dev_close(struct rte_eth_dev *dev);
static int idpf_dev_info_get(struct rte_eth_dev *dev,
			     struct rte_eth_dev_info *dev_info);
static int idpf_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
static int idpf_dev_stats_get(struct rte_eth_dev *dev,
			struct rte_eth_stats *stats);
static int idpf_dev_stats_reset(struct rte_eth_dev *dev);

int
idpf_dev_link_update(struct rte_eth_dev *dev,
		     __rte_unused int wait_to_complete)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	struct rte_eth_link new_link;

	memset(&new_link, 0, sizeof(new_link));

	new_link.link_speed = RTE_ETH_SPEED_NUM_NONE;

	new_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	new_link.link_status = vport->link_up ? RTE_ETH_LINK_UP :
		RTE_ETH_LINK_DOWN;
	new_link.link_autoneg = !(dev->data->dev_conf.link_speeds &
				  RTE_ETH_LINK_SPEED_FIXED);

	return rte_eth_linkstatus_set(dev, &new_link);
}

static const struct eth_dev_ops idpf_eth_dev_ops = {
	.dev_supported_ptypes_get	= idpf_dev_supported_ptypes_get,
	.dev_configure			= idpf_dev_configure,
	.dev_start			= idpf_dev_start,
	.dev_stop			= idpf_dev_stop,
	.dev_close			= idpf_dev_close,
	.rx_queue_start			= idpf_rx_queue_start,
	.rx_queue_stop			= idpf_rx_queue_stop,
	.tx_queue_start			= idpf_tx_queue_start,
	.tx_queue_stop			= idpf_tx_queue_stop,
	.rx_queue_setup			= idpf_rx_queue_setup,
	.rx_queue_release		= idpf_dev_rx_queue_release,
	.tx_queue_setup			= idpf_tx_queue_setup,
	.tx_queue_release		= idpf_dev_tx_queue_release,
	.dev_infos_get			= idpf_dev_info_get,
	.link_update			= idpf_dev_link_update,
	.mtu_set			= idpf_dev_mtu_set,
	.stats_get				= idpf_dev_stats_get,
	.stats_reset			= idpf_dev_stats_reset,
};

static int
idpf_dev_info_get(__rte_unused struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = adapter->caps->max_rx_q;
	dev_info->max_tx_queues = adapter->caps->max_tx_q;
	dev_info->min_rx_bufsize = IDPF_MIN_BUF_SIZE;
	dev_info->max_rx_pktlen = IDPF_MAX_FRAME_SIZE;

	dev_info->max_mtu = dev_info->max_rx_pktlen - IDPF_ETH_OVERHEAD;
	dev_info->min_mtu = RTE_ETHER_MIN_MTU;

	dev_info->flow_type_rss_offloads = IDPF_RSS_OFFLOAD_ALL;
	dev_info->max_mac_addrs = IDPF_NUM_MACADDR_MAX;
	dev_info->dev_capa = RTE_ETH_DEV_CAPA_RUNTIME_RX_QUEUE_SETUP |
		RTE_ETH_DEV_CAPA_RUNTIME_TX_QUEUE_SETUP;
	dev_info->rx_offload_capa =
		RTE_ETH_RX_OFFLOAD_VLAN_STRIP		|
		RTE_ETH_RX_OFFLOAD_QINQ_STRIP		|
		RTE_ETH_RX_OFFLOAD_IPV4_CKSUM		|
		RTE_ETH_RX_OFFLOAD_UDP_CKSUM		|
		RTE_ETH_RX_OFFLOAD_TCP_CKSUM		|
		RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM	|
		RTE_ETH_RX_OFFLOAD_SCATTER		|
		RTE_ETH_RX_OFFLOAD_VLAN_FILTER		|
		RTE_ETH_RX_OFFLOAD_RSS_HASH;

	dev_info->tx_offload_capa =
		RTE_ETH_TX_OFFLOAD_VLAN_INSERT		|
		RTE_ETH_TX_OFFLOAD_QINQ_INSERT		|
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM		|
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM		|
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM	|
		RTE_ETH_TX_OFFLOAD_TCP_TSO		|
		RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO	|
		RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO		|
		RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO		|
		RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO	|
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS		|
		RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_free_thresh = IDPF_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_free_thresh = IDPF_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = IDPF_DEFAULT_TX_RS_THRESH,
		.offloads = 0,
	};

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = IDPF_MAX_RING_DESC,
		.nb_min = IDPF_MIN_RING_DESC,
		.nb_align = IDPF_ALIGN_RING_DESC,
	};

	dev_info->tx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = IDPF_MAX_RING_DESC,
		.nb_min = IDPF_MIN_RING_DESC,
		.nb_align = IDPF_ALIGN_RING_DESC,
	};

	return 0;
}

static int
idpf_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu __rte_unused)
{
	/* mtu setting is forbidden if port is start */
	if (dev->data->dev_started) {
		PMD_DRV_LOG(ERR, "port must be stopped before configuration");
		return -EBUSY;
	}

	return 0;
}

static void
idpf_stat_update(uint64_t *offset, uint64_t *stat)
{
	*stat = *stat - *offset;
}


static void
idpf_update_stats(struct virtchnl2_vport_stats *oes, struct virtchnl2_vport_stats *nes)
{
	idpf_stat_update(&oes->rx_bytes, &nes->rx_bytes);
	idpf_stat_update(&oes->rx_unicast, &nes->rx_unicast);
	idpf_stat_update(&oes->rx_multicast, &nes->rx_multicast);
	idpf_stat_update(&oes->rx_broadcast, &nes->rx_broadcast);
	idpf_stat_update(&oes->rx_discards, &nes->rx_discards);
	idpf_stat_update(&oes->tx_bytes, &nes->tx_bytes);
	idpf_stat_update(&oes->tx_unicast, &nes->tx_unicast);
	idpf_stat_update(&oes->tx_multicast, &nes->tx_multicast);
	idpf_stat_update(&oes->tx_broadcast, &nes->tx_broadcast);
	idpf_stat_update(&oes->tx_errors, &nes->tx_errors);
	idpf_stat_update(&oes->tx_discards, &nes->tx_discards);
}

static int
idpf_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	struct virtchnl2_vport_stats *pstats = NULL;
	int ret;

	ret = idpf_query_stats(vport, &pstats);
	if (ret == 0) {
		uint8_t crc_stats_len = (dev->data->dev_conf.rxmode.offloads &
					 RTE_ETH_RX_OFFLOAD_KEEP_CRC) ? 0 :
					 RTE_ETHER_CRC_LEN;
		idpf_update_stats(&vport->eth_stats_offset, pstats);
		stats->ipackets = pstats->rx_unicast + pstats->rx_multicast +
				pstats->rx_broadcast - pstats->rx_discards;
		stats->opackets = pstats->tx_broadcast + pstats->tx_multicast +
						pstats->tx_unicast;
		stats->imissed = pstats->rx_discards;
		stats->oerrors = pstats->tx_errors + pstats->tx_discards;
		stats->ibytes = pstats->rx_bytes;
		stats->ibytes -= stats->ipackets * crc_stats_len;
		stats->obytes = pstats->tx_bytes;
	} else {
		PMD_DRV_LOG(ERR, "Get statistics failed");
	}
	return ret;
}


static int
idpf_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	struct virtchnl2_vport_stats *pstats = NULL;
	int ret;

	ret = idpf_query_stats(vport, &pstats);
	if (ret != 0)
		return ret;

	/* set stats offset base on current values */
	vport->eth_stats_offset = *pstats;

	return 0;
}

static int
idpf_init_vport_req_info(struct rte_eth_dev *dev)
{
	struct virtchnl2_create_vport *vport_info;
	uint16_t idx = adapter->next_vport_idx;

	if (!adapter->vport_req_info[idx]) {
		adapter->vport_req_info[idx] = rte_zmalloc(NULL,
				    sizeof(struct virtchnl2_create_vport), 0);
		if (!adapter->vport_req_info[idx]) {
			PMD_INIT_LOG(ERR, "Failed to allocate vport_req_info");
			return -1;
		}
	}

	vport_info =
		(struct virtchnl2_create_vport *)adapter->vport_req_info[idx];

	vport_info->vport_type = rte_cpu_to_le_16(VIRTCHNL2_VPORT_TYPE_DEFAULT);
	if (!adapter->txq_model) {
		vport_info->txq_model =
			rte_cpu_to_le_16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
		vport_info->num_tx_q = dev->data->nb_tx_queues;
		vport_info->num_tx_complq =
			dev->data->nb_tx_queues * IDPF_TX_COMPLQ_PER_GRP;
	} else {
		vport_info->txq_model =
			rte_cpu_to_le_16(VIRTCHNL2_QUEUE_MODEL_SINGLE);
		vport_info->num_tx_q = dev->data->nb_tx_queues;
		vport_info->num_tx_complq = 0;
	}
	if (!adapter->rxq_model) {
		vport_info->rxq_model =
			rte_cpu_to_le_16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
		vport_info->num_rx_q = dev->data->nb_rx_queues;
		vport_info->num_rx_bufq =
			dev->data->nb_rx_queues * IDPF_RX_BUFQ_PER_GRP;
	} else {
		vport_info->rxq_model =
			rte_cpu_to_le_16(VIRTCHNL2_QUEUE_MODEL_SINGLE);
		vport_info->num_rx_q = dev->data->nb_rx_queues;
		vport_info->num_rx_bufq = 0;
	}

	return 0;
}

static uint16_t
idpf_get_next_vport_idx(struct idpf_vport **vports, uint16_t max_vport_nb,
			uint16_t cur_vport_idx)
{
	uint16_t vport_idx;
	uint16_t i;

	if (cur_vport_idx < max_vport_nb && !vports[cur_vport_idx + 1]) {
		vport_idx = cur_vport_idx + 1;
		return vport_idx;
	}

	for (i = 0; i < max_vport_nb; i++) {
		if (!vports[i])
			break;
	}

	if (i == max_vport_nb)
		vport_idx = IDPF_INVALID_VPORT_IDX;
	else
		vport_idx = i;

	return vport_idx;
}

#ifndef IDPF_RSS_KEY_LEN
#define IDPF_RSS_KEY_LEN 52
#endif

static int
idpf_init_vport(struct rte_eth_dev *dev)
{
	uint16_t idx = adapter->next_vport_idx;
	struct virtchnl2_create_vport *vport_info =
		(struct virtchnl2_create_vport *)adapter->vport_recv_info[idx];
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	int i;

	vport->adapter = adapter;
	vport->vport_id = vport_info->vport_id;
	vport->txq_model = vport_info->txq_model;
	vport->rxq_model = vport_info->rxq_model;
	vport->num_tx_q = vport_info->num_tx_q;
	vport->num_tx_complq = vport_info->num_tx_complq;
	vport->num_rx_q = vport_info->num_rx_q;
	vport->num_rx_bufq = vport_info->num_rx_bufq;
	vport->max_mtu = vport_info->max_mtu;
	rte_memcpy(vport->default_mac_addr,
		   vport_info->default_mac_addr, ETH_ALEN);
	vport->rss_algorithm = vport_info->rss_algorithm;
	vport->rss_key_size = RTE_MIN(IDPF_RSS_KEY_LEN,
				     vport_info->rss_key_size);
	vport->rss_lut_size = vport_info->rss_lut_size;
	vport->sw_idx = idx;

	for (i = 0; i < vport_info->chunks.num_chunks; i++) {
		if (vport_info->chunks.chunks[i].type ==
		    VIRTCHNL2_QUEUE_TYPE_TX) {
			vport->chunks_info.tx_start_qid =
				vport_info->chunks.chunks[i].start_queue_id;
			vport->chunks_info.tx_qtail_start =
				vport_info->chunks.chunks[i].qtail_reg_start;
			vport->chunks_info.tx_qtail_spacing =
				vport_info->chunks.chunks[i].qtail_reg_spacing;
		} else if (vport_info->chunks.chunks[i].type ==
			 VIRTCHNL2_QUEUE_TYPE_RX) {
			vport->chunks_info.rx_start_qid =
				vport_info->chunks.chunks[i].start_queue_id;
			vport->chunks_info.rx_qtail_start =
				vport_info->chunks.chunks[i].qtail_reg_start;
			vport->chunks_info.rx_qtail_spacing =
				vport_info->chunks.chunks[i].qtail_reg_spacing;
		} else if (vport_info->chunks.chunks[i].type ==
			 VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION) {
			vport->chunks_info.tx_compl_start_qid =
				vport_info->chunks.chunks[i].start_queue_id;
			vport->chunks_info.tx_compl_qtail_start =
				vport_info->chunks.chunks[i].qtail_reg_start;
			vport->chunks_info.tx_compl_qtail_spacing =
				vport_info->chunks.chunks[i].qtail_reg_spacing;
		} else if (vport_info->chunks.chunks[i].type ==
			 VIRTCHNL2_QUEUE_TYPE_RX_BUFFER) {
			vport->chunks_info.rx_buf_start_qid =
				vport_info->chunks.chunks[i].start_queue_id;
			vport->chunks_info.rx_buf_qtail_start =
				vport_info->chunks.chunks[i].qtail_reg_start;
			vport->chunks_info.rx_buf_qtail_spacing =
				vport_info->chunks.chunks[i].qtail_reg_spacing;
		}
	}

	adapter->vports[idx] = vport;
	adapter->cur_vport_nb++;
	adapter->next_vport_idx = idpf_get_next_vport_idx(adapter->vports,
						  adapter->max_vport_nb, idx);
	if (adapter->next_vport_idx == IDPF_INVALID_VPORT_IDX) {
		PMD_INIT_LOG(ERR, "Failed to get next vport id");
		return -1;
	}

	return 0;
}

static int
idpf_config_rss(struct idpf_vport *vport)
{
	int ret;

	ret = idpf_set_rss_key(vport);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to configure RSS key");
		return ret;
	}

	ret = idpf_set_rss_lut(vport);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to configure RSS lut");
		return ret;
	}

	ret = idpf_set_rss_hash(vport);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to configure RSS hash");
		return ret;
	}

	return ret;
}

static int
idpf_init_rss(struct idpf_vport *vport)
{
	struct rte_eth_rss_conf *rss_conf;
	uint16_t i, nb_q, lut_size;
	int ret = 0;

	rss_conf = &vport->dev_data->dev_conf.rx_adv_conf.rss_conf;
	nb_q = vport->num_rx_q;

	vport->rss_key = (uint8_t *)rte_zmalloc("rss_key",
					     vport->rss_key_size, 0);
	if (!vport->rss_key) {
		PMD_INIT_LOG(ERR, "Failed to allocate RSS key");
		ret = -ENOMEM;
		goto err_key;
	}

	lut_size = vport->rss_lut_size;
	vport->rss_lut = (uint32_t *)rte_zmalloc("rss_lut",
					      sizeof(uint32_t) * lut_size, 0);
	if (!vport->rss_lut) {
		PMD_INIT_LOG(ERR, "Failed to allocate RSS lut");
		ret = -ENOMEM;
		goto err_lut;
	}

	if (!rss_conf->rss_key) {
		for (i = 0; i < vport->rss_key_size; i++)
			vport->rss_key[i] = (uint8_t)rte_rand();
	} else {
		rte_memcpy(vport->rss_key, rss_conf->rss_key,
			   RTE_MIN(rss_conf->rss_key_len,
				   vport->rss_key_size));
	}

	for (i = 0; i < lut_size; i++)
		vport->rss_lut[i] = i % nb_q;

	vport->rss_hf = IECM_DEFAULT_RSS_HASH_EXPANDED;

	ret = idpf_config_rss(vport);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to configure RSS");
		goto err_cfg;
	}

	return ret;

err_cfg:
	rte_free(vport->rss_lut);
	vport->rss_lut = NULL;
err_lut:
	rte_free(vport->rss_key);
	vport->rss_key = NULL;
err_key:
	return ret;
}

static int
idpf_dev_configure(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	int ret = 0;

	if (dev->data->dev_conf.rxmode.mq_mode & RTE_ETH_MQ_RX_RSS_FLAG)
		dev->data->dev_conf.rxmode.offloads |=
			RTE_ETH_RX_OFFLOAD_RSS_HASH;

	ret = idpf_init_vport_req_info(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init vport req_info.");
		return ret;
	}

	ret = idpf_create_vport(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to create vport.");
		return ret;
	}

	ret = idpf_init_vport(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init vports.");
		return ret;
	}

	rte_ether_addr_copy((struct rte_ether_addr *)vport->default_mac_addr,
			    &dev->data->mac_addrs[0]);

	if (adapter->caps->rss_caps) {
		ret = idpf_init_rss(vport);
		if (ret) {
			PMD_INIT_LOG(ERR, "Failed to init rss");
			return ret;
		}
	}

	return ret;
}

static int
idpf_config_rx_queues_irqs(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	struct virtchnl2_queue_vector *qv_map;
	struct iecm_hw *hw = &adapter->hw;
	uint32_t dynctl_reg_start;
	uint32_t itrn_reg_start;
	uint32_t dynctl_val, itrn_val;
	uint16_t i;

	qv_map = rte_zmalloc("qv_map",
			dev->data->nb_rx_queues *
			sizeof(struct virtchnl2_queue_vector), 0);
	if (!qv_map) {
		PMD_DRV_LOG(ERR, "Failed to allocate %d queue-vector map",
			    dev->data->nb_rx_queues);
		goto qv_map_alloc_err;
	}

	/* Rx interrupt disabled, Map interrupt only for writeback */

	/* The capability flags adapter->caps->other_caps here should be
	 * compared with bit VIRTCHNL2_CAP_WB_ON_ITR. The if condition should
	 * be updated when the FW can return correct flag bits.
	 */
	if (adapter->caps->other_caps) {
		dynctl_reg_start = vport->recv_vectors->vchunks.vchunks->dynctl_reg_start;
		itrn_reg_start = vport->recv_vectors->vchunks.vchunks->itrn_reg_start;
		dynctl_val = IECM_READ_REG(hw, dynctl_reg_start);
		PMD_DRV_LOG(DEBUG, "Value of dynctl_reg_start is 0x%x", dynctl_val);
		itrn_val = IECM_READ_REG(hw, itrn_reg_start);
		PMD_DRV_LOG(DEBUG, "Value of itrn_reg_start is 0x%x", itrn_val);
		/* Force write-backs by setting WB_ON_ITR bit in DYN_CTL
		 * register. WB_ON_ITR and INTENA are mutually exclusive
		 * bits. Setting WB_ON_ITR bits means TX and RX Descs
		 * are writen back based on ITR expiration irrespective
		 * of INTENA setting.
		 */
		/* TBD: need to tune INTERVAL value for better performance. */
		if (itrn_val)
			IECM_WRITE_REG(hw,
				       dynctl_reg_start,
				       VIRTCHNL2_ITR_IDX_0  <<
				       PF_GLINT_DYN_CTL_ITR_INDX_S |
				       PF_GLINT_DYN_CTL_WB_ON_ITR_M |
				       itrn_val <<
				       PF_GLINT_DYN_CTL_INTERVAL_S);
		else
			IECM_WRITE_REG(hw,
				       dynctl_reg_start,
				       VIRTCHNL2_ITR_IDX_0  <<
				       PF_GLINT_DYN_CTL_ITR_INDX_S |
				       PF_GLINT_DYN_CTL_WB_ON_ITR_M |
				       IDPF_DFLT_INTERVAL <<
				       PF_GLINT_DYN_CTL_INTERVAL_S);
	}
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		/* map all queues to the same vector */
		qv_map[i].queue_id = vport->chunks_info.rx_start_qid + i;
		qv_map[i].vector_id =
			vport->recv_vectors->vchunks.vchunks->start_vector_id;
	}
	vport->qv_map = qv_map;

	if (idpf_config_irq_map_unmap(vport, true)) {
		PMD_DRV_LOG(ERR, "config interrupt mapping failed");
		goto config_irq_map_err;
	}

	return 0;

config_irq_map_err:
	rte_free(vport->qv_map);
	vport->qv_map = NULL;

qv_map_alloc_err:
	return -1;
}

static int
idpf_start_queues(struct rte_eth_dev *dev)
{
	struct idpf_rx_queue *rxq;
	struct idpf_tx_queue *txq;
	int err = 0;
	int i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (!txq || txq->tx_deferred_start)
			continue;
		err = idpf_tx_queue_start(dev, i);
		if (err) {
			PMD_DRV_LOG(ERR, "Fail to start Tx queue %u", i);
			return err;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		if (!rxq || rxq->rx_deferred_start)
			continue;
		err = idpf_rx_queue_start(dev, i);
		if (err) {
			PMD_DRV_LOG(ERR, "Fail to start Rx queue %u", i);
			return err;
		}
	}

	return err;
}

static int
idpf_dev_start(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	uint16_t num_allocated_vectors =
		adapter->caps->num_allocated_vectors;
	uint16_t req_vecs_num;

	PMD_INIT_FUNC_TRACE();

	vport->stopped = 0;

	if (dev->data->mtu > vport->max_mtu) {
		PMD_DRV_LOG(ERR, "MTU should be less than %d", vport->max_mtu);
		goto err_mtu;
	}

	vport->max_pkt_len = dev->data->mtu + IDPF_ETH_OVERHEAD;

	req_vecs_num = IDPF_DFLT_Q_VEC_NUM;
	if (req_vecs_num + used_vecs_num > num_allocated_vectors) {
		PMD_DRV_LOG(ERR, "The accumulated request vectors' number should be less than %d",
			    num_allocated_vectors);
		goto err_mtu;
	}
	if (idpf_alloc_vectors(vport, req_vecs_num)) {
		PMD_DRV_LOG(ERR, "Failed to allocate interrupt vectors");
		goto err_mtu;
	}
	used_vecs_num += req_vecs_num;

	if (idpf_config_rx_queues_irqs(dev)) {
		PMD_DRV_LOG(ERR, "Failed to configure irqs");
		goto err_mtu;
	}

	if (idpf_start_queues(dev)) {
		PMD_DRV_LOG(ERR, "Failed to start queues");
		goto err_mtu;
	}

	idpf_set_rx_function(dev);
	idpf_set_tx_function(dev);

	if (idpf_ena_dis_vport(vport, true)) {
		PMD_DRV_LOG(ERR, "Failed to enable vport");
		goto err_vport;
	}

	if (idpf_dev_stats_reset(dev)) {
		PMD_DRV_LOG(ERR, "Failed to reset stats");
		goto err_vport;
	}
	return 0;

err_vport:
	idpf_stop_queues(dev);
err_mtu:
	return -1;
}

static int
idpf_dev_stop(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	if (vport->stopped == 1)
		return 0;

	if (idpf_ena_dis_vport(vport, false))
		PMD_DRV_LOG(ERR, "disable vport failed");

	idpf_stop_queues(dev);

	if (idpf_config_irq_map_unmap(vport, false))
		PMD_DRV_LOG(ERR, "config interrupt unmapping failed");

	if (idpf_dealloc_vectors(vport))
		PMD_DRV_LOG(ERR, "deallocate interrupt vectors failed");

	vport->stopped = 1;
	dev->data->dev_started = 0;

	return 0;
}

static int
idpf_dev_close(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	idpf_dev_stop(dev);
	idpf_destroy_vport(vport);

	if (vport->rss_lut) {
		rte_free(vport->rss_lut);
		vport->rss_lut = NULL;
	}

	if (vport->rss_key) {
		rte_free(vport->rss_key);
		vport->rss_key = NULL;
	}

	if (vport->recv_vectors) {
		rte_free(vport->recv_vectors);
		vport->recv_vectors = NULL;
	}

	if (vport->qv_map) {
		rte_free(vport->qv_map);
		vport->qv_map = NULL;
	}

	return 0;
}

static int
parse_bool(const char *key, const char *value, void *args)
{
	int *i = (int *)args;
	char *end;
	int num;

	num = strtoul(value, &end, 10);

	if (num != 0 && num != 1) {
		PMD_DRV_LOG(WARNING, "invalid value:\"%s\" for key:\"%s\", "
			"value must be 0 or 1",
			value, key);
		return -1;
	}

	*i = num;
	return 0;
}

static int idpf_parse_devargs(struct rte_eth_dev *dev)
{
	struct rte_devargs *devargs = dev->device->devargs;
	struct rte_kvargs *kvlist;
	int ret;

	if (!devargs)
		return 0;

	kvlist = rte_kvargs_parse(devargs->args, idpf_valid_args);
	if (!kvlist) {
		PMD_INIT_LOG(ERR, "invalid kvargs key");
		return -EINVAL;
	}

	ret = rte_kvargs_process(kvlist, IDPF_TX_SINGLE_Q, &parse_bool,
				 &adapter->txq_model);
	if (ret)
		goto bail;

	ret = rte_kvargs_process(kvlist, IDPF_RX_SINGLE_Q, &parse_bool,
				 &adapter->rxq_model);
	if (ret)
		goto bail;

bail:
	rte_kvargs_free(kvlist);
	return ret;
}

static void
idpf_reset_pf(struct iecm_hw *hw)
{
	uint32_t reg;

	reg = IECM_READ_REG(hw, PFGEN_CTRL);
	IECM_WRITE_REG(hw, PFGEN_CTRL, (reg | PFGEN_CTRL_PFSWR));
}

#define IDPF_RESET_WAIT_CNT 100
static int
idpf_check_pf_reset_done(struct iecm_hw *hw)
{
	uint32_t reg;
	int i;

	for (i = 0; i < IDPF_RESET_WAIT_CNT; i++) {
		reg = IECM_READ_REG(hw, PFGEN_RSTAT);
		if (reg != 0xFFFFFFFF && (reg & PFGEN_RSTAT_PFR_STATE_M))
			return 0;
		rte_delay_ms(1000);
	}

	PMD_INIT_LOG(ERR, "IDPF reset timeout");
	return -EBUSY;
}

#define CTLQ_NUM 2
static int
idpf_init_mbx(struct iecm_hw *hw)
{
	struct iecm_ctlq_create_info ctlq_info[CTLQ_NUM] = {
		{
			.type = IECM_CTLQ_TYPE_MAILBOX_TX,
			.id = IDPF_CTLQ_ID,
			.len = IDPF_CTLQ_LEN,
			.buf_size = IDPF_DFLT_MBX_BUF_SIZE,
			.reg = {
				.head = PF_FW_ATQH,
				.tail = PF_FW_ATQT,
				.len = PF_FW_ATQLEN,
				.bah = PF_FW_ATQBAH,
				.bal = PF_FW_ATQBAL,
				.len_mask = PF_FW_ATQLEN_ATQLEN_M,
				.len_ena_mask = PF_FW_ATQLEN_ATQENABLE_M,
				.head_mask = PF_FW_ATQH_ATQH_M,
			}
		},
		{
			.type = IECM_CTLQ_TYPE_MAILBOX_RX,
			.id = IDPF_CTLQ_ID,
			.len = IDPF_CTLQ_LEN,
			.buf_size = IDPF_DFLT_MBX_BUF_SIZE,
			.reg = {
				.head = PF_FW_ARQH,
				.tail = PF_FW_ARQT,
				.len = PF_FW_ARQLEN,
				.bah = PF_FW_ARQBAH,
				.bal = PF_FW_ARQBAL,
				.len_mask = PF_FW_ARQLEN_ARQLEN_M,
				.len_ena_mask = PF_FW_ARQLEN_ARQENABLE_M,
				.head_mask = PF_FW_ARQH_ARQH_M,
			}
		}
	};
	struct iecm_ctlq_info *ctlq;
	int ret = 0;

	ret = iecm_ctlq_init(hw, CTLQ_NUM, ctlq_info);
	if (ret)
		return ret;

	LIST_FOR_EACH_ENTRY_SAFE(ctlq, NULL, &hw->cq_list_head,
				 struct iecm_ctlq_info, cq_list) {
		if (ctlq->q_id == IDPF_CTLQ_ID && ctlq->cq_type == IECM_CTLQ_TYPE_MAILBOX_TX)
			hw->asq = ctlq;
		if (ctlq->q_id == IDPF_CTLQ_ID && ctlq->cq_type == IECM_CTLQ_TYPE_MAILBOX_RX)
			hw->arq = ctlq;
	}

	if (!hw->asq || !hw->arq) {
		iecm_ctlq_deinit(hw);
		ret = -ENOENT;
	}

	return ret;
}

static int
idpf_adapter_init(struct rte_eth_dev *dev)
{
	struct iecm_hw *hw = &adapter->hw;
	struct rte_pci_device *pci_dev = IDPF_DEV_TO_PCI(dev);
	int ret = 0;

	if (adapter->initialized)
		return 0;

	idpf_set_default_ptype_table(dev);

	hw->hw_addr = (void *)pci_dev->mem_resource[0].addr;
	hw->hw_addr_len = pci_dev->mem_resource[0].len;
	hw->back = adapter;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->device_id = pci_dev->id.device_id;
	hw->subsystem_vendor_id = pci_dev->id.subsystem_vendor_id;

	ret = idpf_parse_devargs(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to parse devargs");
		goto err;
	}

	idpf_reset_pf(hw);
	ret = idpf_check_pf_reset_done(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "IDPF is still resetting");
		goto err;
	}

	ret = idpf_init_mbx(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init mailbox");
		goto err;
	}

	adapter->mbx_resp = rte_zmalloc("idpf_adapter_mbx_resp", IDPF_DFLT_MBX_BUF_SIZE, 0);
	if (!adapter->mbx_resp) {
		PMD_INIT_LOG(ERR, "Failed to allocate idpf_adapter_mbx_resp memory");
		goto err_mbx;
	}

	if (idpf_check_api_version(adapter)) {
		PMD_INIT_LOG(ERR, "Failed to check api version");
		goto err_api;
	}

	adapter->caps = rte_zmalloc("idpf_caps",
			       sizeof(struct virtchnl2_get_capabilities), 0);
	if (!adapter->caps) {
		PMD_INIT_LOG(ERR, "Failed to allocate idpf_caps memory");
		goto err_api;
	}

	if (idpf_get_caps(adapter)) {
		PMD_INIT_LOG(ERR, "Failed to get capabilities");
		goto err_caps;
	}

	adapter->max_vport_nb = adapter->caps->max_vports;

	adapter->vport_req_info = rte_zmalloc("vport_req_info",
					      adapter->max_vport_nb *
					      sizeof(*adapter->vport_req_info),
					      0);
	if (!adapter->vport_req_info) {
		PMD_INIT_LOG(ERR, "Failed to allocate vport_req_info memory");
		goto err_caps;
	}

	adapter->vport_recv_info = rte_zmalloc("vport_recv_info",
					       adapter->max_vport_nb *
					       sizeof(*adapter->vport_recv_info),
					       0);
	if (!adapter->vport_recv_info) {
		PMD_INIT_LOG(ERR, "Failed to allocate vport_recv_info memory");
		goto err_vport_recv_info;
	}

	adapter->vports = rte_zmalloc("vports",
				      adapter->max_vport_nb *
				      sizeof(*adapter->vports),
				      0);
	if (!adapter->vports) {
		PMD_INIT_LOG(ERR, "Failed to allocate vports memory");
		goto err_vports;
	}

	adapter->max_rxq_per_msg = (IDPF_DFLT_MBX_BUF_SIZE -
			       sizeof(struct virtchnl2_config_rx_queues)) /
			       sizeof(struct virtchnl2_rxq_info);
	adapter->max_txq_per_msg = (IDPF_DFLT_MBX_BUF_SIZE -
			       sizeof(struct virtchnl2_config_tx_queues)) /
			       sizeof(struct virtchnl2_txq_info);

	adapter->cur_vport_nb = 0;
	adapter->next_vport_idx = 0;
	adapter->initialized = true;

	return ret;

err_vports:
	rte_free(adapter->vports);
	adapter->vports = NULL;
err_vport_recv_info:
	rte_free(adapter->vport_req_info);
	adapter->vport_req_info = NULL;
err_caps:
	rte_free(adapter->caps);
	adapter->caps = NULL;
err_api:
	rte_free(adapter->mbx_resp);
	adapter->mbx_resp = NULL;
err_mbx:
	iecm_ctlq_deinit(hw);
err:
	return -1;
}


static int
idpf_dev_init(struct rte_eth_dev *dev, __rte_unused void *init_params)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	dev->dev_ops = &idpf_eth_dev_ops;

	/* for secondary processes, we don't initialise any further as primary
	 * has already done this work.
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		idpf_set_rx_function(dev);
		idpf_set_tx_function(dev);
		return ret;
	}

	ret = idpf_adapter_init(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init adapter.");
		return ret;
	}

	dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	vport->dev_data = dev->data;

	dev->data->mac_addrs = rte_zmalloc(NULL, RTE_ETHER_ADDR_LEN, 0);
	if (dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Cannot allocate mac_addr memory.");
		ret = -ENOMEM;
		goto err;
	}

err:
	return ret;
}

static int
idpf_dev_uninit(struct rte_eth_dev *dev)
{
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -EPERM;

	idpf_dev_close(dev);

	return 0;
}

static const struct rte_pci_id pci_id_idpf_map[] = {
	{ RTE_PCI_DEVICE(IECM_INTEL_VENDOR_ID, IECM_DEV_ID_PF) },
	{ .vendor_id = 0, /* sentinel */ },
};

static int
idpf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	      struct rte_pci_device *pci_dev)
{
	struct rte_eth_devargs eth_da = { .nb_representor_ports = 0 };
	char name[RTE_ETH_NAME_MAX_LEN];
	int i, retval;

	if (pci_dev->device.devargs) {
		retval = rte_eth_devargs_parse(pci_dev->device.devargs->args,
				&eth_da);
		if (retval)
			return retval;
	}

	if (!eth_da.nb_representor_ports) {
		PMD_INIT_LOG(ERR, "Failed to probe, need to add representor devargs.");
		return -1;
	}

	if (!adapter) {
		adapter = (struct idpf_adapter *)rte_zmalloc("idpf_adapter",
					     sizeof(struct idpf_adapter), 0);
		if (!adapter) {
			PMD_INIT_LOG(ERR, "Failed to allocate adapter.");
			return -1;
		}
	}

	for (i = 0; i < eth_da.nb_representor_ports; i++) {
		snprintf(name, sizeof(name), "idpf_vport_%d",
			 eth_da.representor_ports[i]);
		retval = rte_eth_dev_create(&pci_dev->device, name,
					    sizeof(struct idpf_vport),
					    NULL, NULL, idpf_dev_init,
					    NULL);
		if (retval)
			PMD_DRV_LOG(ERR, "failed to creat vport %d", i);
	}

	return 0;
}

static void
idpf_adapter_rel(struct idpf_adapter *adapter)
{
	struct iecm_hw *hw = &adapter->hw;
	int i;

	iecm_ctlq_deinit(hw);

	if (adapter->caps) {
		rte_free(adapter->caps);
		adapter->caps = NULL;
	}

	if (adapter->mbx_resp) {
		rte_free(adapter->mbx_resp);
		adapter->mbx_resp = NULL;
	}

	if (adapter->vport_req_info) {
		for (i = 0; i < adapter->max_vport_nb; i++) {
			if (adapter->vport_req_info[i]) {
				rte_free(adapter->vport_req_info[i]);
				adapter->vport_req_info[i] = NULL;
			}
		}
		rte_free(adapter->vport_req_info);
		adapter->vport_req_info = NULL;
	}

	if (adapter->vport_recv_info) {
		for (i = 0; i < adapter->max_vport_nb; i++) {
			if (adapter->vport_recv_info[i]) {
				rte_free(adapter->vport_recv_info[i]);
				adapter->vport_recv_info[i] = NULL;
			}
		}
	}

	if (adapter->vports) {
		/* Needn't free adapter->vports[i] since it's private data */
		rte_free(adapter->vports);
		adapter->vports = NULL;
	}
}

static int
idpf_pci_remove(struct rte_pci_device *pci_dev)
{
	if (adapter) {
		idpf_adapter_rel(adapter);
		rte_free(adapter);
		adapter = NULL;
	}

	return rte_eth_dev_pci_generic_remove(pci_dev, idpf_dev_uninit);
}

static struct rte_pci_driver rte_idpf_pmd = {
	.id_table	= pci_id_idpf_map,
	.drv_flags	= RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC |
			  RTE_PCI_DRV_PROBE_AGAIN,
	.probe		= idpf_pci_probe,
	.remove		= idpf_pci_remove,
};

/**
 * Driver initialization routine.
 * Invoked once at EAL init time.
 * Register itself as the [Poll Mode] Driver of PCI devices.
 */
RTE_PMD_REGISTER_PCI(net_idpf, rte_idpf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_idpf, pci_id_idpf_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ice, "* igb_uio | uio_pci_generic | vfio-pci");

RTE_LOG_REGISTER_SUFFIX(idpf_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(idpf_logtype_driver, driver, NOTICE);
