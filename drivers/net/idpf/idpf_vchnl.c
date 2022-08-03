/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>
#include <rte_byteorder.h>
#include <rte_common.h>

#include <rte_debug.h>
#include <rte_atomic.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_dev.h>

#include "idpf_ethdev.h"
#include "idpf_rxtx.h"

#include "base/iecm_prototype.h"

#define IDPF_CTLQ_LEN	64

static int
idpf_vc_clean(struct idpf_adapter *adapter)
{
	struct iecm_ctlq_msg *q_msg[IDPF_CTLQ_LEN];
	uint16_t num_q_msg = IDPF_CTLQ_LEN;
	struct iecm_dma_mem *dma_mem;
	int err = 0;
	uint32_t i;

	for (i = 0; i < 10; i++) {
		err = iecm_ctlq_clean_sq(adapter->hw.asq, &num_q_msg, q_msg);
		msleep(20);
		if (num_q_msg)
			break;
	}
	if (err)
		goto error;

	/* Empty queue is not an error */
	for (i = 0; i < num_q_msg; i++) {
		dma_mem = q_msg[i]->ctx.indirect.payload;
		if (dma_mem) {
			iecm_free_dma_mem(&adapter->hw, dma_mem);
			rte_free(dma_mem);
		}
		rte_free(q_msg[i]);
	}

error:
	return err;
}

static int
idpf_send_vc_msg(struct idpf_adapter *adapter, enum virtchnl_ops op,
		 uint16_t msg_size, uint8_t *msg)
{
	struct iecm_ctlq_msg *ctlq_msg;
	struct iecm_dma_mem *dma_mem;
	int err = 0;

	err = idpf_vc_clean(adapter);
	if (err)
		goto err;

	ctlq_msg = (struct iecm_ctlq_msg *)rte_zmalloc(NULL,
				sizeof(struct iecm_ctlq_msg), 0);
	if (!ctlq_msg) {
		err = -ENOMEM;
		goto err;
	}

	dma_mem = (struct iecm_dma_mem *)rte_zmalloc(NULL,
				sizeof(struct iecm_dma_mem), 0);
	if (!dma_mem) {
		err = -ENOMEM;
		goto dma_mem_error;
	}

	dma_mem->size = IDPF_DFLT_MBX_BUF_SIZE;
	iecm_alloc_dma_mem(&adapter->hw, dma_mem, dma_mem->size);
	if (!dma_mem->va) {
		err = -ENOMEM;
		goto dma_alloc_error;
	}

	memcpy(dma_mem->va, msg, msg_size);

	ctlq_msg->opcode = iecm_mbq_opc_send_msg_to_pf;
	ctlq_msg->func_id = 0;
	ctlq_msg->data_len = msg_size;
	ctlq_msg->cookie.mbx.chnl_opcode = op;
	ctlq_msg->cookie.mbx.chnl_retval = VIRTCHNL_STATUS_SUCCESS;
	ctlq_msg->ctx.indirect.payload = dma_mem;

	err = iecm_ctlq_send(&adapter->hw, adapter->hw.asq, 1, ctlq_msg);
	if (err)
		goto send_error;

	return err;

send_error:
	iecm_free_dma_mem(&adapter->hw, dma_mem);
dma_alloc_error:
	rte_free(dma_mem);
dma_mem_error:
	rte_free(ctlq_msg);
err:
	return err;
}

static enum idpf_vc_result
idpf_read_msg_from_ipf(struct idpf_adapter *adapter, uint16_t buf_len,
		       uint8_t *buf)
{
	struct iecm_hw *hw = &adapter->hw;
	struct iecm_ctlq_msg ctlq_msg;
	struct iecm_dma_mem *dma_mem = NULL;
	enum idpf_vc_result result = IDPF_MSG_NON;
	enum virtchnl_ops opcode;
	uint16_t pending = 1;
	int ret;

	ret = iecm_ctlq_recv(hw->arq, &pending, &ctlq_msg);
	if (ret) {
		PMD_DRV_LOG(DEBUG, "Can't read msg from AQ");
		if (ret != IECM_ERR_CTLQ_NO_WORK)
			result = IDPF_MSG_ERR;
		return result;
	}

	rte_memcpy(buf, ctlq_msg.ctx.indirect.payload->va, buf_len);

	opcode = (enum virtchnl_ops)rte_le_to_cpu_32(ctlq_msg.cookie.mbx.chnl_opcode);
	adapter->cmd_retval =
		(enum virtchnl_status_code)rte_le_to_cpu_32(ctlq_msg.cookie.mbx.chnl_retval);

	PMD_DRV_LOG(DEBUG, "CQ from ipf carries opcode %u, retval %d",
		    opcode, adapter->cmd_retval);

	if (opcode == VIRTCHNL2_OP_EVENT) {
		struct virtchnl2_event *ve =
			(struct virtchnl2_event *)ctlq_msg.ctx.indirect.payload->va;

		result = IDPF_MSG_SYS;
		switch (ve->event) {
		case VIRTCHNL2_EVENT_LINK_CHANGE:
			/* TBD */
			break;
		default:
			PMD_DRV_LOG(ERR, "%s: Unknown event %d from ipf",
				    __func__, ve->event);
			break;
		}
	} else {
		/* async reply msg on command issued by pf previously */
		result = IDPF_MSG_CMD;
		if (opcode != adapter->pend_cmd) {
			PMD_DRV_LOG(WARNING, "command mismatch, expect %u, get %u",
				    adapter->pend_cmd, opcode);
			result = IDPF_MSG_ERR;
		}
	}

	if (ctlq_msg.data_len)
		dma_mem = ctlq_msg.ctx.indirect.payload;
	else
		pending = 0;

	ret = iecm_ctlq_post_rx_buffs(hw, hw->arq, &pending, &dma_mem);
	if (ret && dma_mem)
		iecm_free_dma_mem(hw, dma_mem);

	return result;
}

#define MAX_TRY_TIMES 200
#define ASQ_DELAY_MS  10

static int
idpf_execute_vc_cmd(struct idpf_adapter *adapter, struct idpf_cmd_info *args)
{
	enum idpf_vc_result result;
	int err = 0;
	int i = 0;
	int ret;

	if (_atomic_set_cmd(adapter, args->ops))
		return -1;

	ret = idpf_send_vc_msg(adapter, args->ops,
			       args->in_args_size,
			       args->in_args);
	if (ret) {
		PMD_DRV_LOG(ERR, "fail to send cmd %d", args->ops);
		_clear_cmd(adapter);
		return ret;
	}

	switch (args->ops) {
	case VIRTCHNL_OP_VERSION:
	case VIRTCHNL2_OP_GET_CAPS:
	case VIRTCHNL2_OP_CREATE_VPORT:
	case VIRTCHNL2_OP_DESTROY_VPORT:
	case VIRTCHNL2_OP_SET_RSS_KEY:
	case VIRTCHNL2_OP_SET_RSS_LUT:
	case VIRTCHNL2_OP_SET_RSS_HASH:
	case VIRTCHNL2_OP_CONFIG_RX_QUEUES:
	case VIRTCHNL2_OP_CONFIG_TX_QUEUES:
	case VIRTCHNL2_OP_ENABLE_QUEUES:
	case VIRTCHNL2_OP_DISABLE_QUEUES:
	case VIRTCHNL2_OP_ENABLE_VPORT:
	case VIRTCHNL2_OP_DISABLE_VPORT:
	case VIRTCHNL2_OP_GET_STATS:
		/* for init virtchnl ops, need to poll the response */
		do {
			result = idpf_read_msg_from_ipf(adapter,
							args->out_size,
							args->out_buffer);
			if (result == IDPF_MSG_CMD)
				break;
			rte_delay_ms(ASQ_DELAY_MS);
		} while (i++ < MAX_TRY_TIMES);
		if (i >= MAX_TRY_TIMES ||
		    adapter->cmd_retval != VIRTCHNL_STATUS_SUCCESS) {
			err = -1;
			PMD_DRV_LOG(ERR, "No response or return failure (%d) for cmd %d",
				    adapter->cmd_retval, args->ops);
		}
		_clear_cmd(adapter);
		break;
	default:
		/* For other virtchnl ops in running time,
		 * wait for the cmd done flag.
		 */
		do {
			if (adapter->pend_cmd == VIRTCHNL_OP_UNKNOWN)
				break;
			rte_delay_ms(ASQ_DELAY_MS);
			/* If don't read msg or read sys event, continue */
		} while (i++ < MAX_TRY_TIMES);
		/* If there's no response is received, clear command */
		if (i >= MAX_TRY_TIMES  ||
		    adapter->cmd_retval != VIRTCHNL_STATUS_SUCCESS) {
			err = -1;
			PMD_DRV_LOG(ERR, "No response or return failure (%d) for cmd %d",
				    adapter->cmd_retval, args->ops);
			_clear_cmd(adapter);
		}
		break;
	}

	return err;
}

int
idpf_check_api_version(struct idpf_adapter *adapter)
{
	struct virtchnl_version_info version;
	struct idpf_cmd_info args;
	int err;

	memset(&version, 0, sizeof(struct virtchnl_version_info));
	version.major = VIRTCHNL_VERSION_MAJOR_2;
	version.minor = VIRTCHNL_VERSION_MINOR_0;

	args.ops = VIRTCHNL_OP_VERSION;
	args.in_args = (uint8_t *)&version;
	args.in_args_size = sizeof(version);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err) {
		PMD_DRV_LOG(ERR,
			    "Failed to execute command of VIRTCHNL_OP_VERSION");
		return err;
	}

	return err;
}

int
idpf_get_caps(struct idpf_adapter *adapter)
{
	struct virtchnl2_get_capabilities caps_msg;
	struct idpf_cmd_info args;
	int err;

	 memset(&caps_msg, 0, sizeof(struct virtchnl2_get_capabilities));
	 caps_msg.csum_caps =
		 VIRTCHNL2_CAP_TX_CSUM_L3_IPV4		|
		 VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_TCP	|
		 VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_UDP	|
		 VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|
		 VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_TCP	|
		 VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_UDP	|
		 VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|
		 VIRTCHNL2_CAP_TX_CSUM_GENERIC		|
		 VIRTCHNL2_CAP_RX_CSUM_L3_IPV4		|
		 VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|
		 VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|
		 VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|
		 VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|
		 VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP	|
		 VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP	|
		 VIRTCHNL2_CAP_RX_CSUM_GENERIC;

	 caps_msg.seg_caps =
		 VIRTCHNL2_CAP_SEG_IPV4_TCP		|
		 VIRTCHNL2_CAP_SEG_IPV4_UDP		|
		 VIRTCHNL2_CAP_SEG_IPV4_SCTP		|
		 VIRTCHNL2_CAP_SEG_IPV6_TCP		|
		 VIRTCHNL2_CAP_SEG_IPV6_UDP		|
		 VIRTCHNL2_CAP_SEG_IPV6_SCTP		|
		 VIRTCHNL2_CAP_SEG_GENERIC;

	 caps_msg.rss_caps =
		 VIRTCHNL2_CAP_RSS_IPV4_TCP		|
		 VIRTCHNL2_CAP_RSS_IPV4_UDP		|
		 VIRTCHNL2_CAP_RSS_IPV4_SCTP		|
		 VIRTCHNL2_CAP_RSS_IPV4_OTHER		|
		 VIRTCHNL2_CAP_RSS_IPV6_TCP		|
		 VIRTCHNL2_CAP_RSS_IPV6_UDP		|
		 VIRTCHNL2_CAP_RSS_IPV6_SCTP		|
		 VIRTCHNL2_CAP_RSS_IPV6_OTHER		|
		 VIRTCHNL2_CAP_RSS_IPV4_AH		|
		 VIRTCHNL2_CAP_RSS_IPV4_ESP		|
		 VIRTCHNL2_CAP_RSS_IPV4_AH_ESP		|
		 VIRTCHNL2_CAP_RSS_IPV6_AH		|
		 VIRTCHNL2_CAP_RSS_IPV6_ESP		|
		 VIRTCHNL2_CAP_RSS_IPV6_AH_ESP;

	 caps_msg.hsplit_caps =
		 VIRTCHNL2_CAP_RX_HSPLIT_AT_L2		|
		 VIRTCHNL2_CAP_RX_HSPLIT_AT_L3		|
		 VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|
		 VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6;

	 caps_msg.rsc_caps =
		 VIRTCHNL2_CAP_RSC_IPV4_TCP		|
		 VIRTCHNL2_CAP_RSC_IPV4_SCTP		|
		 VIRTCHNL2_CAP_RSC_IPV6_TCP		|
		 VIRTCHNL2_CAP_RSC_IPV6_SCTP;

	 caps_msg.other_caps =
		 VIRTCHNL2_CAP_RDMA			|
		 VIRTCHNL2_CAP_SRIOV			|
		 VIRTCHNL2_CAP_MACFILTER		|
		 VIRTCHNL2_CAP_FLOW_DIRECTOR		|
		 VIRTCHNL2_CAP_SPLITQ_QSCHED		|
		 VIRTCHNL2_CAP_CRC			|
		 VIRTCHNL2_CAP_WB_ON_ITR		|
		 VIRTCHNL2_CAP_PROMISC			|
		 VIRTCHNL2_CAP_LINK_SPEED		|
		 VIRTCHNL2_CAP_VLAN;

	args.ops = VIRTCHNL2_OP_GET_CAPS;
	args.in_args = (uint8_t *)&caps_msg;
	args.in_args_size = sizeof(caps_msg);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err) {
		PMD_DRV_LOG(ERR,
			    "Failed to execute command of VIRTCHNL2_OP_GET_CAPS");
		return err;
	}

	rte_memcpy(adapter->caps, args.out_buffer, sizeof(caps_msg));

	return err;
}

int
idpf_create_vport(__rte_unused struct rte_eth_dev *dev)
{
	uint16_t idx = adapter->next_vport_idx;
	struct virtchnl2_create_vport *vport_req_info =
		(struct virtchnl2_create_vport *)adapter->vport_req_info[idx];
	struct virtchnl2_create_vport vport_msg;
	struct idpf_cmd_info args;
	int err = -1;

	memset(&vport_msg, 0, sizeof(struct virtchnl2_create_vport));
	vport_msg.vport_type = vport_req_info->vport_type;
	vport_msg.txq_model = vport_req_info->txq_model;
	vport_msg.rxq_model = vport_req_info->rxq_model;
	vport_msg.num_tx_q = vport_req_info->num_tx_q;
	vport_msg.num_tx_complq = vport_req_info->num_tx_complq;
	vport_msg.num_rx_q = vport_req_info->num_rx_q;
	vport_msg.num_rx_bufq = vport_req_info->num_rx_bufq;

	memset(&args, 0, sizeof(args));
	args.ops = VIRTCHNL2_OP_CREATE_VPORT;
	args.in_args = (uint8_t *)&vport_msg;
	args.in_args_size = sizeof(vport_msg);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err) {
		PMD_DRV_LOG(ERR,
			    "Failed to execute command of VIRTCHNL2_OP_CREATE_VPORT");
		return err;
	}

	if (!adapter->vport_recv_info[idx]) {
		adapter->vport_recv_info[idx] = rte_zmalloc(NULL,
						    IDPF_DFLT_MBX_BUF_SIZE, 0);
		if (!adapter->vport_recv_info[idx]) {
			PMD_INIT_LOG(ERR, "Failed to alloc vport_recv_info.");
			return err;
		}
	}
	rte_memcpy(adapter->vport_recv_info[idx], args.out_buffer,
		   IDPF_DFLT_MBX_BUF_SIZE);
	return err;
}

int
idpf_destroy_vport(struct idpf_vport *vport)
{
	struct virtchnl2_vport vc_vport;
	struct idpf_cmd_info args;
	int err;

	vc_vport.vport_id = vport->vport_id;

	memset(&args, 0, sizeof(args));
	args.ops = VIRTCHNL2_OP_DESTROY_VPORT;
	args.in_args = (uint8_t *)&vc_vport;
	args.in_args_size = sizeof(vc_vport);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err) {
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_DESTROY_VPORT");
		return err;
	}

	return err;
}

int
idpf_set_rss_key(struct idpf_vport *vport)
{
	struct virtchnl2_rss_key *rss_key;
	struct idpf_cmd_info args;
	int len, err;

	len = sizeof(*rss_key) + sizeof(rss_key->key[0]) *
		(vport->rss_key_size - 1);
	rss_key = rte_zmalloc("rss_key", len, 0);
	if (!rss_key)
		return -ENOMEM;

	rss_key->vport_id = vport->vport_id;
	rss_key->key_len = vport->rss_key_size;
	rte_memcpy(rss_key->key, vport->rss_key,
		   sizeof(rss_key->key[0]) * vport->rss_key_size);

	memset(&args, 0, sizeof(args));
	args.ops = VIRTCHNL2_OP_SET_RSS_KEY;
	args.in_args = (uint8_t *)rss_key;
	args.in_args_size = len;
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err) {
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_SET_RSS_KEY");
		return err;
	}

	rte_free(rss_key);
	return err;
}

int
idpf_set_rss_lut(struct idpf_vport *vport)
{
	struct virtchnl2_rss_lut *rss_lut;
	struct idpf_cmd_info args;
	int len, err;

	len = sizeof(*rss_lut) + sizeof(rss_lut->lut[0]) *
		(vport->rss_lut_size - 1);
	rss_lut = rte_zmalloc("rss_lut", len, 0);
	if (!rss_lut)
		return -ENOMEM;

	rss_lut->vport_id = vport->vport_id;
	rss_lut->lut_entries = vport->rss_lut_size;
	rte_memcpy(rss_lut->lut, vport->rss_lut,
		   sizeof(rss_lut->lut[0]) * vport->rss_lut_size);

	memset(&args, 0, sizeof(args));
	args.ops = VIRTCHNL2_OP_SET_RSS_LUT;
	args.in_args = (uint8_t *)rss_lut;
	args.in_args_size = len;
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err)
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_SET_RSS_LUT");

	rte_free(rss_lut);
	return err;
}

int
idpf_set_rss_hash(struct idpf_vport *vport)
{
	struct virtchnl2_rss_hash rss_hash;
	struct idpf_cmd_info args;
	int err;

	memset(&rss_hash, 0, sizeof(rss_hash));
	rss_hash.ptype_groups = vport->rss_hf;
	rss_hash.vport_id = vport->vport_id;

	memset(&args, 0, sizeof(args));
	args.ops = VIRTCHNL2_OP_SET_RSS_HASH;
	args.in_args = (uint8_t *)&rss_hash;
	args.in_args_size = sizeof(rss_hash);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err)
		PMD_DRV_LOG(ERR, "Failed to execute command of OP_SET_RSS_HASH");

	return err;
}

#define IDPF_RX_BUF_STRIDE		64
int
idpf_config_rxqs(struct idpf_vport *vport)
{
	struct idpf_rx_queue **rxq =
		(struct idpf_rx_queue **)vport->dev_data->rx_queues;
	struct virtchnl2_config_rx_queues *vc_rxqs = NULL;
	struct virtchnl2_rxq_info *rxq_info;
	struct idpf_cmd_info args;
	uint16_t total_qs, num_qs;
	int size, err, i, j;
	int k = 0;

	total_qs = vport->num_rx_q + vport->num_rx_bufq;
	while (total_qs) {
		if (total_qs > adapter->max_rxq_per_msg) {
			num_qs = adapter->max_rxq_per_msg;
			total_qs -= adapter->max_rxq_per_msg;
		} else {
			num_qs = total_qs;
			total_qs = 0;
		}

		size = sizeof(*vc_rxqs) + (num_qs - 1) *
			sizeof(struct virtchnl2_rxq_info);
		vc_rxqs = rte_zmalloc("cfg_rxqs", size, 0);
		if (vc_rxqs == NULL) {
			PMD_DRV_LOG(ERR, "Failed to allocate virtchnl2_config_rx_queues");
			err = -ENOMEM;
			break;
		}
		vc_rxqs->vport_id = vport->vport_id;
		vc_rxqs->num_qinfo = num_qs;
		if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE) {
			for (i = 0; i < num_qs; i++, k++) {
				rxq_info = &vc_rxqs->qinfo[i];
				rxq_info->dma_ring_addr = rxq[k]->rx_ring_phys_addr;
				rxq_info->type = VIRTCHNL2_QUEUE_TYPE_RX;
				rxq_info->queue_id = rxq[k]->queue_id;
				rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
				rxq_info->data_buffer_size = rxq[k]->rx_buf_len;
				rxq_info->max_pkt_size = vport->max_pkt_len;

				rxq_info->desc_ids = VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M;
				rxq_info->qflags |= VIRTCHNL2_RX_DESC_SIZE_32BYTE;

				rxq_info->ring_len = rxq[k]->nb_rx_desc;
			}
		} else {
			for (i = 0; i < num_qs / 3; i++, k++) {
				/* Rx queue */
				rxq_info = &vc_rxqs->qinfo[i * 3];
				rxq_info->dma_ring_addr =
					rxq[k]->rx_ring_phys_addr;
				rxq_info->type = VIRTCHNL2_QUEUE_TYPE_RX;
				rxq_info->queue_id = rxq[k]->queue_id;
				rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
				rxq_info->data_buffer_size = rxq[k]->rx_buf_len;
				rxq_info->max_pkt_size = vport->max_pkt_len;

				rxq_info->desc_ids = VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M;
				rxq_info->qflags |= VIRTCHNL2_RX_DESC_SIZE_32BYTE;

				rxq_info->ring_len = rxq[k]->nb_rx_desc;
				rxq_info->rx_bufq1_id = rxq[k]->bufq1->queue_id;
				rxq_info->rx_bufq2_id = rxq[k]->bufq2->queue_id;
				rxq_info->rx_buffer_low_watermark = 64;

				/* Buffer queue */
				for (j = 1; j <= IDPF_RX_BUFQ_PER_GRP; j++) {
					struct idpf_rx_queue *bufq = j == 1 ?
						rxq[k]->bufq1 : rxq[k]->bufq2;
					rxq_info = &vc_rxqs->qinfo[i * 3 + j];
					rxq_info->dma_ring_addr =
						bufq->rx_ring_phys_addr;
					rxq_info->type =
						VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
					rxq_info->queue_id = bufq->queue_id;
					rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
					rxq_info->data_buffer_size = bufq->rx_buf_len;
					rxq_info->desc_ids =
						VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M;
					rxq_info->ring_len = bufq->nb_rx_desc;

					rxq_info->buffer_notif_stride =
						IDPF_RX_BUF_STRIDE;
					rxq_info->rx_buffer_low_watermark = 64;
				}
			}
		}
		memset(&args, 0, sizeof(args));
		args.ops = VIRTCHNL2_OP_CONFIG_RX_QUEUES;
		args.in_args = (uint8_t *)vc_rxqs;
		args.in_args_size = size;
		args.out_buffer = adapter->mbx_resp;
		args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

		err = idpf_execute_vc_cmd(adapter, &args);
		rte_free(vc_rxqs);
		if (err) {
			PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_CONFIG_RX_QUEUES");
			break;
		}
	}

	return err;
}

int
idpf_config_rxq(struct idpf_vport *vport, uint16_t rxq_id)
{
	struct idpf_rx_queue **rxq =
		(struct idpf_rx_queue **)vport->dev_data->rx_queues;
	struct virtchnl2_config_rx_queues *vc_rxqs = NULL;
	struct virtchnl2_rxq_info *rxq_info;
	struct idpf_cmd_info args;
	uint16_t num_qs;
	int size, err, i;

	if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
		num_qs = IDPF_RXQ_PER_GRP;
	else
		num_qs = IDPF_RXQ_PER_GRP + IDPF_RX_BUFQ_PER_GRP;

	size = sizeof(*vc_rxqs) + (num_qs - 1) *
		sizeof(struct virtchnl2_rxq_info);
	vc_rxqs = rte_zmalloc("cfg_rxqs", size, 0);
	if (vc_rxqs == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate virtchnl2_config_rx_queues");
		err = -ENOMEM;
		return err;
	}
	vc_rxqs->vport_id = vport->vport_id;
	vc_rxqs->num_qinfo = num_qs;
	if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE) {
		rxq_info = &vc_rxqs->qinfo[0];
		rxq_info->dma_ring_addr = rxq[rxq_id]->rx_ring_phys_addr;
		rxq_info->type = VIRTCHNL2_QUEUE_TYPE_RX;
		rxq_info->queue_id = rxq[rxq_id]->queue_id;
		rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
		rxq_info->data_buffer_size = rxq[rxq_id]->rx_buf_len;
		rxq_info->max_pkt_size = vport->max_pkt_len;

		rxq_info->desc_ids = VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M;
		rxq_info->qflags |= VIRTCHNL2_RX_DESC_SIZE_32BYTE;

		rxq_info->ring_len = rxq[rxq_id]->nb_rx_desc;
	}  else {
		/* Rx queue */
		rxq_info = &vc_rxqs->qinfo[0];
		rxq_info->dma_ring_addr = rxq[rxq_id]->rx_ring_phys_addr;
		rxq_info->type = VIRTCHNL2_QUEUE_TYPE_RX;
		rxq_info->queue_id = rxq[rxq_id]->queue_id;
		rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
		rxq_info->data_buffer_size = rxq[rxq_id]->rx_buf_len;
		rxq_info->max_pkt_size = vport->max_pkt_len;

		rxq_info->desc_ids = VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M;
		rxq_info->qflags |= VIRTCHNL2_RX_DESC_SIZE_32BYTE;

		rxq_info->ring_len = rxq[rxq_id]->nb_rx_desc;
		rxq_info->rx_bufq1_id = rxq[rxq_id]->bufq1->queue_id;
		rxq_info->rx_bufq2_id = rxq[rxq_id]->bufq2->queue_id;
		rxq_info->rx_buffer_low_watermark = 64;

		/* Buffer queue */
		for (i = 1; i <= IDPF_RX_BUFQ_PER_GRP; i++) {
			struct idpf_rx_queue *bufq =
				i == 1 ? rxq[rxq_id]->bufq1 : rxq[rxq_id]->bufq2;
			rxq_info = &vc_rxqs->qinfo[i];
			rxq_info->dma_ring_addr = bufq->rx_ring_phys_addr;
			rxq_info->type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
			rxq_info->queue_id = bufq->queue_id;
			rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
			rxq_info->data_buffer_size = bufq->rx_buf_len;
			rxq_info->desc_ids = VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M;
			rxq_info->ring_len = bufq->nb_rx_desc;

			rxq_info->buffer_notif_stride = IDPF_RX_BUF_STRIDE;
			rxq_info->rx_buffer_low_watermark = 64;
		}
	}

	memset(&args, 0, sizeof(args));
	args.ops = VIRTCHNL2_OP_CONFIG_RX_QUEUES;
	args.in_args = (uint8_t *)vc_rxqs;
	args.in_args_size = size;
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	rte_free(vc_rxqs);
	if (err)
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_CONFIG_RX_QUEUES");

	return err;
}

int
idpf_config_txqs(struct idpf_vport *vport)
{
	struct idpf_tx_queue **txq =
		(struct idpf_tx_queue **)vport->dev_data->tx_queues;
	struct virtchnl2_config_tx_queues *vc_txqs = NULL;
	struct virtchnl2_txq_info *txq_info;
	struct idpf_cmd_info args;
	uint16_t total_qs, num_qs;
	int size, err, i;
	int k = 0;

	total_qs = vport->num_tx_q + vport->num_tx_complq;
	while (total_qs) {
		if (total_qs > adapter->max_txq_per_msg) {
			num_qs = adapter->max_txq_per_msg;
			total_qs -= adapter->max_txq_per_msg;
		} else {
			num_qs = total_qs;
			total_qs = 0;
		}
		size = sizeof(*vc_txqs) + (num_qs - 1) *
			sizeof(struct virtchnl2_txq_info);
		vc_txqs = rte_zmalloc("cfg_txqs", size, 0);
		if (vc_txqs == NULL) {
			PMD_DRV_LOG(ERR, "Failed to allocate virtchnl2_config_tx_queues");
			err = -ENOMEM;
			break;
		}
		vc_txqs->vport_id = vport->vport_id;
		vc_txqs->num_qinfo = num_qs;
		if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE) {
			for (i = 0; i < num_qs; i++, k++) {
				txq_info = &vc_txqs->qinfo[i];
				txq_info->dma_ring_addr = txq[k]->tx_ring_phys_addr;
				txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX;
				txq_info->queue_id = txq[k]->queue_id;
				txq_info->model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
				txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_QUEUE;
				txq_info->ring_len = txq[k]->nb_tx_desc;
			}
		} else {
			for (i = 0; i < num_qs / 2; i++, k++) {
				/* txq info */
				txq_info = &vc_txqs->qinfo[2 * i];
				txq_info->dma_ring_addr = txq[k]->tx_ring_phys_addr;
				txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX;
				txq_info->queue_id = txq[k]->queue_id;
				txq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
				txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_FLOW;
				txq_info->ring_len = txq[k]->nb_tx_desc;
				txq_info->tx_compl_queue_id =
					txq[k]->complq->queue_id;
				txq_info->relative_queue_id = txq_info->queue_id;

				/* tx completion queue info */
				txq_info = &vc_txqs->qinfo[2 * i + 1];
				txq_info->dma_ring_addr =
					txq[k]->complq->tx_ring_phys_addr;
				txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
				txq_info->queue_id = txq[k]->complq->queue_id;
				txq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
				txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_FLOW;
				txq_info->ring_len = txq[k]->complq->nb_tx_desc;
			}
		}

		memset(&args, 0, sizeof(args));
		args.ops = VIRTCHNL2_OP_CONFIG_TX_QUEUES;
		args.in_args = (uint8_t *)vc_txqs;
		args.in_args_size = size;
		args.out_buffer = adapter->mbx_resp;
		args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

		err = idpf_execute_vc_cmd(adapter, &args);
		rte_free(vc_txqs);
		if (err) {
			PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_CONFIG_TX_QUEUES");
			break;
		}
	}

	return err;
}

int
idpf_config_txq(struct idpf_vport *vport, uint16_t txq_id)
{
	struct idpf_tx_queue **txq =
		(struct idpf_tx_queue **)vport->dev_data->tx_queues;
	struct virtchnl2_config_tx_queues *vc_txqs = NULL;
	struct virtchnl2_txq_info *txq_info;
	struct idpf_cmd_info args;
	uint16_t num_qs;
	int size, err;

	if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
		num_qs = IDPF_TXQ_PER_GRP;
	else
		num_qs = IDPF_TXQ_PER_GRP + IDPF_TX_COMPLQ_PER_GRP;

	size = sizeof(*vc_txqs) + (num_qs - 1) *
		sizeof(struct virtchnl2_txq_info);
	vc_txqs = rte_zmalloc("cfg_txqs", size, 0);
	if (vc_txqs == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate virtchnl2_config_tx_queues");
		err = -ENOMEM;
		return err;
	}
	vc_txqs->vport_id = vport->vport_id;
	vc_txqs->num_qinfo = num_qs;

	if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE) {
		txq_info = &vc_txqs->qinfo[0];
		txq_info->dma_ring_addr = txq[txq_id]->tx_ring_phys_addr;
		txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX;
		txq_info->queue_id = txq[txq_id]->queue_id;
		txq_info->model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
		txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_QUEUE;
		txq_info->ring_len = txq[txq_id]->nb_tx_desc;
	} else {
		/* txq info */
		txq_info = &vc_txqs->qinfo[0];
		txq_info->dma_ring_addr = txq[txq_id]->tx_ring_phys_addr;
		txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX;
		txq_info->queue_id = txq[txq_id]->queue_id;
		txq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
		txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_FLOW;
		txq_info->ring_len = txq[txq_id]->nb_tx_desc;
		txq_info->tx_compl_queue_id = txq[txq_id]->complq->queue_id;
		txq_info->relative_queue_id = txq_info->queue_id;

		/* tx completion queue info */
		txq_info = &vc_txqs->qinfo[1];
		txq_info->dma_ring_addr = txq[txq_id]->complq->tx_ring_phys_addr;
		txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
		txq_info->queue_id = txq[txq_id]->complq->queue_id;
		txq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
		txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_FLOW;
		txq_info->ring_len = txq[txq_id]->complq->nb_tx_desc;
	}

	memset(&args, 0, sizeof(args));
	args.ops = VIRTCHNL2_OP_CONFIG_TX_QUEUES;
	args.in_args = (uint8_t *)vc_txqs;
	args.in_args_size = size;
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	rte_free(vc_txqs);
	if (err)
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_CONFIG_TX_QUEUES");

	return err;
}

static int
idpf_ena_dis_one_queue(struct idpf_vport *vport, uint16_t qid,
		       uint32_t type, bool on)
{
	struct virtchnl2_del_ena_dis_queues *queue_select;
	struct virtchnl2_queue_chunk *queue_chunk;
	struct idpf_cmd_info args;
	int err, len;

	len = sizeof(struct virtchnl2_del_ena_dis_queues);
	queue_select = rte_zmalloc("queue_select", len, 0);
	if (!queue_select)
		return -ENOMEM;

	queue_chunk = queue_select->chunks.chunks;
	queue_select->chunks.num_chunks = 1;
	queue_select->vport_id = vport->vport_id;

	queue_chunk->type = type;
	queue_chunk->start_queue_id = qid;
	queue_chunk->num_queues = 1;

	args.ops = on ? VIRTCHNL2_OP_ENABLE_QUEUES :
		VIRTCHNL2_OP_DISABLE_QUEUES;
	args.in_args = (u8 *)queue_select;
	args.in_args_size = len;
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
	err = idpf_execute_vc_cmd(adapter, &args);
	if (err)
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_%s_QUEUES",
			    on ? "ENABLE" : "DISABLE");

	rte_free(queue_select);
	return err;
}

int
idpf_switch_queue(struct idpf_vport *vport, uint16_t qid,
		 bool rx, bool on)
{
	uint32_t type;
	int err, queue_id;

	/* switch txq/rxq */
	type = rx ? VIRTCHNL2_QUEUE_TYPE_RX : VIRTCHNL2_QUEUE_TYPE_TX;

	if (type == VIRTCHNL2_QUEUE_TYPE_RX)
		queue_id = vport->chunks_info.rx_start_qid + qid;
	else
		queue_id = vport->chunks_info.tx_start_qid + qid;
	err = idpf_ena_dis_one_queue(vport, queue_id, type, on);
	if (err)
		return err;

	/* switch tx completion queue */
	if (!rx && vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
		queue_id = vport->chunks_info.tx_compl_start_qid + qid;
		err = idpf_ena_dis_one_queue(vport, queue_id, type, on);
		if (err)
			return err;
	}

	/* switch rx buffer queue */
	if (rx && vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
		queue_id = vport->chunks_info.rx_buf_start_qid + 2 * qid;
		err = idpf_ena_dis_one_queue(vport, queue_id, type, on);
		if (err)
			return err;
		queue_id++;
		err = idpf_ena_dis_one_queue(vport, queue_id, type, on);
		if (err)
			return err;
	}

	return err;
}

#define IDPF_RXTX_QUEUE_CHUNKS_NUM	2
int idpf_ena_dis_queues(struct idpf_vport *vport, bool enable)
{
	struct virtchnl2_del_ena_dis_queues *queue_select;
	struct virtchnl2_queue_chunk *queue_chunk;
	uint32_t type;
	struct idpf_cmd_info args;
	uint16_t num_chunks;
	int err, len;

	num_chunks = IDPF_RXTX_QUEUE_CHUNKS_NUM;
	if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT)
		num_chunks++;
	if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT)
		num_chunks++;

	len = sizeof(struct virtchnl2_del_ena_dis_queues) +
		sizeof(struct virtchnl2_queue_chunk) * (num_chunks - 1);
	queue_select = rte_zmalloc("queue_select", len, 0);
	if (queue_select == NULL)
		return -ENOMEM;

	queue_chunk = queue_select->chunks.chunks;
	queue_select->chunks.num_chunks = num_chunks;
	queue_select->vport_id = vport->vport_id;

	type = VIRTCHNL_QUEUE_TYPE_RX;
	queue_chunk[type].type = type;
	queue_chunk[type].start_queue_id = vport->chunks_info.rx_start_qid;
	queue_chunk[type].num_queues = vport->num_rx_q;

	type = VIRTCHNL2_QUEUE_TYPE_TX;
	queue_chunk[type].type = type;
	queue_chunk[type].start_queue_id = vport->chunks_info.tx_start_qid;
	queue_chunk[type].num_queues = vport->num_tx_q;

	if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
		queue_chunk[type].type = type;
		queue_chunk[type].start_queue_id =
			vport->chunks_info.rx_buf_start_qid;
		queue_chunk[type].num_queues = vport->num_rx_bufq;
	}

	if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
		queue_chunk[type].type = type;
		queue_chunk[type].start_queue_id =
			vport->chunks_info.tx_compl_start_qid;
		queue_chunk[type].num_queues = vport->num_tx_complq;
	}

	args.ops = enable ? VIRTCHNL2_OP_ENABLE_QUEUES :
		VIRTCHNL2_OP_DISABLE_QUEUES;
	args.in_args = (u8 *)queue_select;
	args.in_args_size = len;
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
	err = idpf_execute_vc_cmd(adapter, &args);
	if (err)
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_%s_QUEUES",
			    enable ? "ENABLE" : "DISABLE");

	rte_free(queue_select);
	return err;
}

int
idpf_ena_dis_vport(struct idpf_vport *vport, bool enable)
{
	struct virtchnl2_vport vc_vport;
	struct idpf_cmd_info args;
	int err;

	vc_vport.vport_id = vport->vport_id;
	args.ops = enable ? VIRTCHNL2_OP_ENABLE_VPORT :
			    VIRTCHNL2_OP_DISABLE_VPORT;
	args.in_args = (u8 *)&vc_vport;
	args.in_args_size = sizeof(vc_vport);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err) {
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_%s_VPORT",
			    enable ? "ENABLE" : "DISABLE");
	}

	return err;
}

int
idpf_query_stats(struct idpf_vport *vport,
		struct virtchnl2_vport_stats **pstats)
{
	struct virtchnl2_vport vc_vport;
	struct idpf_cmd_info args;
	int err;

	vc_vport.vport_id = vport->vport_id;
	args.ops = VIRTCHNL2_OP_GET_STATS;
	args.in_args = (u8 *)&vc_vport;
	args.in_args_size = sizeof(vc_vport);
	args.out_buffer = adapter->mbx_resp;
	args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

	err = idpf_execute_vc_cmd(adapter, &args);
	if (err) {
		PMD_DRV_LOG(ERR, "Failed to execute command of VIRTCHNL2_OP_GET_STATS");
		*pstats = NULL;
		return err;
	}
	*pstats = (struct virtchnl2_vport_stats *)args.out_buffer;
	return 0;
}

