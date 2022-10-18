/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <rte_atomic.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_dev.h>

#include "idpf_ethdev.h"
#include "idpf_rxtx.h"

#define IDPF_TX_SINGLE_Q	"tx_single"
#define IDPF_RX_SINGLE_Q	"rx_single"
#define IDPF_VPORT		"vport"

struct idpf_adapter_list adapter_list;
bool adapter_list_init;

static const char * const idpf_valid_args[] = {
	IDPF_TX_SINGLE_Q,
	IDPF_RX_SINGLE_Q,
	IDPF_VPORT,
	NULL
};

static int idpf_dev_configure(struct rte_eth_dev *dev);
static int idpf_dev_start(struct rte_eth_dev *dev);
static int idpf_dev_stop(struct rte_eth_dev *dev);
static int idpf_dev_close(struct rte_eth_dev *dev);
static int idpf_dev_info_get(struct rte_eth_dev *dev,
			     struct rte_eth_dev_info *dev_info);
static void idpf_adapter_rel(struct idpf_adapter *adapter);

static const struct eth_dev_ops idpf_eth_dev_ops = {
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
idpf_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct idpf_vport *vport = dev->data->dev_private;
	struct idpf_adapter *adapter = vport->adapter;

	dev_info->max_rx_queues = adapter->caps->max_rx_q;
	dev_info->max_tx_queues = adapter->caps->max_tx_q;
	dev_info->min_rx_bufsize = IDPF_MIN_BUF_SIZE;
	dev_info->max_rx_pktlen = IDPF_MAX_FRAME_SIZE;

	dev_info->max_mac_addrs = IDPF_NUM_MACADDR_MAX;
	dev_info->dev_capa = RTE_ETH_DEV_CAPA_RUNTIME_RX_QUEUE_SETUP |
		RTE_ETH_DEV_CAPA_RUNTIME_TX_QUEUE_SETUP;

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

	dev_info->default_rxportconf.burst_size = IDPF_RX_MAX_BURST;
	dev_info->default_txportconf.burst_size = IDPF_TX_MAX_BURST;
	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;

	return 0;
}

static int
idpf_init_vport_req_info(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport = dev->data->dev_private;
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_info;
	uint16_t idx = adapter->cur_vport_idx;

	if (idx == IDPF_INVALID_VPORT_IDX) {
		PMD_INIT_LOG(ERR, "Invalid vport index.");
		return -1;
	}

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
		vport_info->num_tx_q = IDPF_DEFAULT_TXQ_NUM;
		vport_info->num_tx_complq =
			IDPF_DEFAULT_TXQ_NUM * IDPF_TX_COMPLQ_PER_GRP;
	} else {
		vport_info->txq_model =
			rte_cpu_to_le_16(VIRTCHNL2_QUEUE_MODEL_SINGLE);
		vport_info->num_tx_q = IDPF_DEFAULT_TXQ_NUM;
		vport_info->num_tx_complq = 0;
	}
	if (!adapter->rxq_model) {
		vport_info->rxq_model =
			rte_cpu_to_le_16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
		vport_info->num_rx_q = IDPF_DEFAULT_RXQ_NUM;
		vport_info->num_rx_bufq =
			IDPF_DEFAULT_RXQ_NUM * IDPF_RX_BUFQ_PER_GRP;
	} else {
		vport_info->rxq_model =
			rte_cpu_to_le_16(VIRTCHNL2_QUEUE_MODEL_SINGLE);
		vport_info->num_rx_q = IDPF_DEFAULT_RXQ_NUM;
		vport_info->num_rx_bufq = 0;
	}

	return 0;
}

static uint16_t
idpf_parse_devarg_id(char *name)
{
	uint16_t val;
	char *p;

	p = strstr(name, "vport_");
	p += sizeof("vport_") - 1;

	val = strtoul(p, NULL, 10);

	return val;
}

static int
idpf_init_vport(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport = dev->data->dev_private;
	struct idpf_adapter *adapter = vport->adapter;
	uint16_t idx = adapter->cur_vport_idx;
	struct virtchnl2_create_vport *vport_info =
		(struct virtchnl2_create_vport *)adapter->vport_recv_info[idx];
	int i;

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

	vport->devarg_id = idpf_parse_devarg_id(dev->data->name);
	vport->dev_data = dev->data;
	vport->stopped = 1;

	adapter->vports[idx] = vport;

	return 0;
}

static int
idpf_dev_configure(__rte_unused struct rte_eth_dev *dev)
{
	if (dev->data->nb_tx_queues > IDPF_DEFAULT_TXQ_NUM ||
	    dev->data->nb_rx_queues > IDPF_DEFAULT_RXQ_NUM) {
		PMD_INIT_LOG(ERR, "Invalid queue number.");
		return -EINVAL;
	}

	return 0;
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
	struct idpf_vport *vport = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	vport->stopped = 0;

	if (idpf_start_queues(dev)) {
		PMD_DRV_LOG(ERR, "Failed to start queues");
		goto err_mtu;
	}

	if (idpf_vc_ena_dis_vport(vport, true)) {
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
	struct idpf_vport *vport = dev->data->dev_private;

	PMD_INIT_FUNC_TRACE();

	if (vport->stopped == 1)
		return 0;

	if (idpf_vc_ena_dis_vport(vport, false))
		PMD_DRV_LOG(ERR, "disable vport failed");

	idpf_stop_queues(dev);

	vport->stopped = 1;
	dev->data->dev_started = 0;

	return 0;
}

static int
idpf_dev_close(struct rte_eth_dev *dev)
{
	struct idpf_vport *vport = dev->data->dev_private;
	struct idpf_adapter *adapter = vport->adapter;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	idpf_dev_stop(dev);
	idpf_vc_destroy_vport(vport);

	adapter->cur_vports &= ~BIT(vport->devarg_id);

	rte_free(vport);
	dev->data->dev_private = NULL;

	return 0;
}

static int
insert_value(struct idpf_adapter *adapter, uint16_t id)
{
	uint16_t i;

	for (i = 0; i < adapter->req_vport_nb; i++) {
		if (adapter->req_vports[i] == id)
			return 0;
	}

	if (adapter->req_vport_nb >= RTE_DIM(adapter->req_vports)) {
		PMD_INIT_LOG(ERR, "Total vport number can't be > %d",
			     IDPF_MAX_VPORT_NUM);
		return -1;
	}

	adapter->req_vports[adapter->req_vport_nb] = id;
	adapter->req_vport_nb++;

	return 0;
}

static const char *
parse_range(const char *value, struct idpf_adapter *adapter)
{
	uint16_t lo, hi, i;
	int n = 0;
	int result;
	const char *pos = value;

	result = sscanf(value, "%hu%n-%hu%n", &lo, &n, &hi, &n);
	if (result == 1) {
		if (lo >= IDPF_MAX_VPORT_NUM)
			return NULL;
		if (insert_value(adapter, lo))
			return NULL;
	} else if (result == 2) {
		if (lo > hi || hi >= IDPF_MAX_VPORT_NUM)
			return NULL;
		for (i = lo; i <= hi; i++) {
			if (insert_value(adapter, i))
				return NULL;
		}
	} else {
		return NULL;
	}

	return pos + n;
}

static int
parse_vport(const char *key, const char *value, void *args)
{
	struct idpf_adapter *adapter = (struct idpf_adapter *)args;
	const char *pos = value;
	int i;

	adapter->req_vport_nb = 0;

	if (*pos == '[')
		pos++;

	while (1) {
		pos = parse_range(pos, adapter);
		if (pos == NULL) {
			PMD_INIT_LOG(ERR, "invalid value:\"%s\" for key:\"%s\", ",
				     value, key);
			return -1;
		}
		if (*pos != ',')
			break;
		pos++;
	}

	if (*value == '[' && *pos != ']') {
		PMD_INIT_LOG(ERR, "invalid value:\"%s\" for key:\"%s\", ",
			     value, key);
		return -1;
	}

	if (adapter->cur_vport_nb + adapter->req_vport_nb >
	    IDPF_MAX_VPORT_NUM) {
		PMD_INIT_LOG(ERR, "Total vport number can't be > %d",
			     IDPF_MAX_VPORT_NUM);
		return -1;
	}

	for (i = 0; i < adapter->req_vport_nb; i++) {
		if (!(adapter->cur_vports & BIT(adapter->req_vports[i]))) {
			adapter->cur_vports |= BIT(adapter->req_vports[i]);
			adapter->cur_vport_nb++;
		} else {
			PMD_INIT_LOG(ERR, "Vport %d has been created",
				     adapter->req_vports[i]);
			return -1;
		}
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
		PMD_INIT_LOG(ERR, "invalid value:\"%s\" for key:\"%s\", value must be 0 or 1",
			value, key);
		return -1;
	}

	*i = num;
	return 0;
}

static int
idpf_parse_devargs(struct rte_pci_device *pci_dev, struct idpf_adapter *adapter)
{
	struct rte_devargs *devargs = pci_dev->device.devargs;
	struct rte_kvargs *kvlist;
	int ret;

	if (!devargs)
		return 0;

	kvlist = rte_kvargs_parse(devargs->args, idpf_valid_args);
	if (!kvlist) {
		PMD_INIT_LOG(ERR, "invalid kvargs key");
		return -EINVAL;
	}

	ret = rte_kvargs_process(kvlist, IDPF_VPORT, &parse_vport,
				 adapter);
	if (ret)
		goto bail;

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
idpf_reset_pf(struct idpf_hw *hw)
{
	uint32_t reg;

	reg = IDPF_READ_REG(hw, PFGEN_CTRL);
	IDPF_WRITE_REG(hw, PFGEN_CTRL, (reg | PFGEN_CTRL_PFSWR));
}

#define IDPF_RESET_WAIT_CNT 100
static int
idpf_check_pf_reset_done(struct idpf_hw *hw)
{
	uint32_t reg;
	int i;

	for (i = 0; i < IDPF_RESET_WAIT_CNT; i++) {
		reg = IDPF_READ_REG(hw, PFGEN_RSTAT);
		if (reg != 0xFFFFFFFF && (reg & PFGEN_RSTAT_PFR_STATE_M))
			return 0;
		rte_delay_ms(1000);
	}

	PMD_INIT_LOG(ERR, "IDPF reset timeout");
	return -EBUSY;
}

#define CTLQ_NUM 2
static int
idpf_init_mbx(struct idpf_hw *hw)
{
	struct idpf_ctlq_create_info ctlq_info[CTLQ_NUM] = {
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_TX,
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
			.type = IDPF_CTLQ_TYPE_MAILBOX_RX,
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
	struct idpf_ctlq_info *ctlq;
	int ret;

	ret = idpf_ctlq_init(hw, CTLQ_NUM, ctlq_info);
	if (ret)
		return ret;

	LIST_FOR_EACH_ENTRY_SAFE(ctlq, NULL, &hw->cq_list_head,
				 struct idpf_ctlq_info, cq_list) {
		if (ctlq->q_id == IDPF_CTLQ_ID &&
		    ctlq->cq_type == IDPF_CTLQ_TYPE_MAILBOX_TX)
			hw->asq = ctlq;
		if (ctlq->q_id == IDPF_CTLQ_ID &&
		    ctlq->cq_type == IDPF_CTLQ_TYPE_MAILBOX_RX)
			hw->arq = ctlq;
	}

	if (!hw->asq || !hw->arq) {
		idpf_ctlq_deinit(hw);
		ret = -ENOENT;
	}

	return ret;
}

static int
idpf_adapter_init(struct rte_pci_device *pci_dev, struct idpf_adapter *adapter)
{
	struct idpf_hw *hw = &adapter->hw;
	int ret = 0;

	hw->hw_addr = (void *)pci_dev->mem_resource[0].addr;
	hw->hw_addr_len = pci_dev->mem_resource[0].len;
	hw->back = adapter;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->device_id = pci_dev->id.device_id;
	hw->subsystem_vendor_id = pci_dev->id.subsystem_vendor_id;

	strncpy(adapter->name, pci_dev->device.name, PCI_PRI_STR_SIZE);

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

	adapter->mbx_resp = rte_zmalloc("idpf_adapter_mbx_resp",
					IDPF_DFLT_MBX_BUF_SIZE, 0);
	if (!adapter->mbx_resp) {
		PMD_INIT_LOG(ERR, "Failed to allocate idpf_adapter_mbx_resp memory");
		goto err_mbx;
	}

	if (idpf_vc_check_api_version(adapter)) {
		PMD_INIT_LOG(ERR, "Failed to check api version");
		goto err_api;
	}

	adapter->caps = rte_zmalloc("idpf_caps",
				sizeof(struct virtchnl2_get_capabilities), 0);
	if (!adapter->caps) {
		PMD_INIT_LOG(ERR, "Failed to allocate idpf_caps memory");
		goto err_api;
	}

	if (idpf_vc_get_caps(adapter)) {
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

	adapter->cur_vports = 0;
	adapter->cur_vport_nb = 0;

	return ret;

err_vports:
	rte_free(adapter->vport_recv_info);
	adapter->vport_recv_info = NULL;
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
	idpf_ctlq_deinit(hw);
err:
	return -1;
}

static uint16_t
idpf_get_vport_idx(struct idpf_vport **vports, uint16_t max_vport_nb)
{
	uint16_t vport_idx;
	uint16_t i;

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

static int
idpf_dev_init(struct rte_eth_dev *dev, void *init_params)
{
	struct idpf_vport *vport = dev->data->dev_private;
	struct idpf_adapter *adapter = init_params;
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	dev->dev_ops = &idpf_eth_dev_ops;
	vport->adapter = adapter;

	/* for secondary processes, we don't initialise any further as primary
	 * has already done this work.
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return ret;

	dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	ret = idpf_init_vport_req_info(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init vport req_info.");
		goto err;
	}

	ret = idpf_vc_create_vport(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to create vport.");
		goto err_create_vport;
	}

	ret = idpf_init_vport(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init vports.");
		goto err_init_vport;
	}

	adapter->cur_vport_idx = idpf_get_vport_idx(adapter->vports,
						    adapter->max_vport_nb);

	dev->data->mac_addrs = rte_zmalloc(NULL, RTE_ETHER_ADDR_LEN, 0);
	if (dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Cannot allocate mac_addr memory.");
		ret = -ENOMEM;
		goto err_init_vport;
	}

	rte_ether_addr_copy((struct rte_ether_addr *)vport->default_mac_addr,
			    &dev->data->mac_addrs[0]);

	return 0;

err_init_vport:
	idpf_vc_destroy_vport(vport);
err_create_vport:
	rte_free(vport->adapter->vport_req_info[vport->adapter->cur_vport_idx]);
err:
	return ret;
}

static const struct rte_pci_id pci_id_idpf_map[] = {
	{ RTE_PCI_DEVICE(IDPF_INTEL_VENDOR_ID, IDPF_DEV_ID_PF) },
	{ .vendor_id = 0, /* sentinel */ },
};

struct idpf_adapter *
idpf_find_adapter(struct rte_pci_device *pci_dev)
{
	struct idpf_adapter *adapter;

	TAILQ_FOREACH(adapter, &adapter_list, next) {
		if (!strncmp(adapter->name, pci_dev->device.name, PCI_PRI_STR_SIZE))
			return adapter;
	}

	return NULL;
}

static int
idpf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	       struct rte_pci_device *pci_dev)
{
	struct idpf_adapter *adapter;
	char name[RTE_ETH_NAME_MAX_LEN];
	int i, retval;
	bool first_probe = FALSE;

	if (!adapter_list_init) {
		TAILQ_INIT(&adapter_list);
		adapter_list_init = true;
	}

	adapter = idpf_find_adapter(pci_dev);
	if (!adapter) {
		first_probe = TRUE;
		adapter = (struct idpf_adapter *)rte_zmalloc("idpf_adapter",
						sizeof(struct idpf_adapter), 0);
		if (!adapter) {
			PMD_INIT_LOG(ERR, "Failed to allocate adapter.");
			return -1;
		}

		retval = idpf_adapter_init(pci_dev, adapter);
		if (retval) {
			PMD_INIT_LOG(ERR, "Failed to init adapter.");
			return retval;
		}

		TAILQ_INSERT_TAIL(&adapter_list, adapter, next);
	}

	retval = idpf_parse_devargs(pci_dev, adapter);
	if (retval) {
		PMD_INIT_LOG(ERR, "Failed to parse private devargs");
		goto err;
	}

	for (i = 0; i < adapter->req_vport_nb; i++) {
		snprintf(name, sizeof(name), "idpf_%s_vport_%d",
			 pci_dev->device.name,
			 adapter->req_vports[i]);
		retval = rte_eth_dev_create(&pci_dev->device, name,
					    sizeof(struct idpf_vport),
					    NULL, NULL, idpf_dev_init,
					    adapter);
		if (retval)
			PMD_DRV_LOG(ERR, "failed to creat vport %d",
				    adapter->req_vports[i]);
	}

	return 0;

err:
	if (first_probe) {
		TAILQ_REMOVE(&adapter_list, adapter, next);
		idpf_adapter_rel(adapter);
		rte_free(adapter);
	}
	return retval;
}

static void
idpf_adapter_rel(struct idpf_adapter *adapter)
{
	struct idpf_hw *hw = &adapter->hw;
	int i;

	idpf_ctlq_deinit(hw);

	rte_free(adapter->caps);
	adapter->caps = NULL;

	rte_free(adapter->mbx_resp);
	adapter->mbx_resp = NULL;

	if (adapter->vport_req_info) {
		for (i = 0; i < adapter->max_vport_nb; i++) {
			rte_free(adapter->vport_req_info[i]);
			adapter->vport_req_info[i] = NULL;
		}
		rte_free(adapter->vport_req_info);
		adapter->vport_req_info = NULL;
	}

	if (adapter->vport_recv_info) {
		for (i = 0; i < adapter->max_vport_nb; i++) {
			rte_free(adapter->vport_recv_info[i]);
			adapter->vport_recv_info[i] = NULL;
		}
		rte_free(adapter->vport_recv_info);
		adapter->vport_recv_info = NULL;
	}

	rte_free(adapter->vports);
	adapter->vports = NULL;
}

static int
idpf_pci_remove(struct rte_pci_device *pci_dev)
{
	struct idpf_adapter *adapter = idpf_find_adapter(pci_dev);
	uint16_t port_id;

	/* Ethdev created can be found RTE_ETH_FOREACH_DEV_OF through rte_device */
	RTE_ETH_FOREACH_DEV_OF(port_id, &pci_dev->device) {
			rte_eth_dev_close(port_id);
	}

	TAILQ_REMOVE(&adapter_list, adapter, next);
	idpf_adapter_rel(adapter);
	rte_free(adapter);

	return 0;
}

static struct rte_pci_driver rte_idpf_pmd = {
	.id_table	= pci_id_idpf_map,
	.drv_flags	= RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_PROBE_AGAIN,
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
