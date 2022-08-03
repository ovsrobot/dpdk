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

#define REPRESENTOR		"representor"

struct idpf_adapter *adapter;
uint16_t used_vecs_num;

static const char * const idpf_valid_args[] = {
	REPRESENTOR,
	NULL
};

static int idpf_dev_configure(struct rte_eth_dev *dev);
static int idpf_dev_start(struct rte_eth_dev *dev);
static int idpf_dev_stop(struct rte_eth_dev *dev);
static int idpf_dev_close(struct rte_eth_dev *dev);
static int idpf_dev_info_get(struct rte_eth_dev *dev,
			     struct rte_eth_dev_info *dev_info);

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
idpf_init_vport_req_info(__rte_unused struct rte_eth_dev *dev)
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
idpf_dev_configure(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport =
		(struct idpf_vport *)dev->data->dev_private;
	int ret = 0;

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

	return ret;
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

	PMD_INIT_FUNC_TRACE();

	vport->stopped = 0;

	if (idpf_start_queues(dev)) {
		PMD_DRV_LOG(ERR, "Failed to start queues");
		goto err_mtu;
	}

	if (idpf_ena_dis_vport(vport, true)) {
		PMD_DRV_LOG(ERR, "Failed to enable vport");
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

	return 0;
}

static int idpf_parse_devargs(struct rte_eth_dev *dev)
{
	struct rte_devargs *devargs = dev->device->devargs;
	struct rte_kvargs *kvlist;
	int ret = 0;

	if (!devargs)
		return 0;

	kvlist = rte_kvargs_parse(devargs->args, idpf_valid_args);
	if (!kvlist) {
		PMD_INIT_LOG(ERR, "invalid kvargs key");
		return -EINVAL;
	}

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
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return ret;

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
