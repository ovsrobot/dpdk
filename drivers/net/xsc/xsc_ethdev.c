/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#include <net/if.h>

#include <ethdev_pci.h>

#include "xsc_log.h"
#include "xsc_defs.h"
#include "xsc_dev.h"
#include "xsc_ethdev.h"
#include "xsc_utils.h"
#include "xsc_ctrl.h"
#include "xsc_rxtx.h"

static __rte_always_inline struct xsc_rxq_data *
xsc_rxq_get(struct rte_eth_dev *dev, uint16_t idx)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	if (priv->rxqs != NULL && (*priv->rxqs)[idx] != NULL)
		return (*priv->rxqs)[idx];
	return NULL;
}

static __rte_always_inline struct xsc_txq_data *
xsc_txq_get(struct rte_eth_dev *dev, uint16_t idx)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	if (priv->txqs != NULL && (*priv->txqs)[idx] != NULL)
		return (*priv->txqs)[idx];
	return NULL;
}

static int
xsc_rss_modify_cmd(struct xsc_ethdev_priv *priv, uint8_t *rss_key,
		   uint8_t rss_key_len)
{
	struct xsc_cmd_modify_nic_hca_mbox_in in = {};
	struct xsc_cmd_modify_nic_hca_mbox_out out = {};
	uint8_t rss_caps_mask = 0;
	int ret, key_len = 0;

	in.hdr.opcode = rte_cpu_to_be_16(XSC_CMD_OP_MODIFY_NIC_HCA);

	key_len = RTE_MIN(rss_key_len, XSC_RSS_HASH_KEY_LEN);
	rte_memcpy(in.rss.hash_key, rss_key, key_len);
	rss_caps_mask |= BIT(XSC_RSS_HASH_KEY_UPDATE);

	in.rss.caps_mask = rss_caps_mask;
	in.rss.rss_en = 1;
	in.nic.caps_mask = rte_cpu_to_be_16(BIT(XSC_TBM_CAP_RSS));
	in.nic.caps = in.nic.caps_mask;

	ret = xsc_mailbox_exec(priv->xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret != 0 || out.hdr.status != 0)
		return -1;
	return 0;
}

static int
xsc_ethdev_rss_hash_conf_get(struct rte_eth_dev *dev,
			     struct rte_eth_rss_conf *rss_conf)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	if (!rss_conf) {
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (rss_conf->rss_key != NULL &&
		rss_conf->rss_key_len >= priv->rss_conf.rss_key_len) {
		memcpy(rss_conf->rss_key, priv->rss_conf.rss_key,
		       priv->rss_conf.rss_key_len);
	}
	rss_conf->rss_key_len = priv->rss_conf.rss_key_len;
	rss_conf->rss_hf = priv->rss_conf.rss_hf;
	return 0;
}

static int
xsc_ethdev_rss_hash_update(struct rte_eth_dev *dev,
			   struct rte_eth_rss_conf *rss_conf)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	int ret = 0;

	if (rss_conf->rss_key_len > XSC_RSS_HASH_KEY_LEN ||
		rss_conf->rss_key == NULL) {
		PMD_DRV_LOG(ERR, "Xsc pmd key len is %d bigger than %d",
			    rss_conf->rss_key_len, XSC_RSS_HASH_KEY_LEN);
		return -EINVAL;
	}

	ret = xsc_rss_modify_cmd(priv, rss_conf->rss_key, rss_conf->rss_key_len);
	if (ret == 0) {
		rte_memcpy(priv->rss_conf.rss_key, rss_conf->rss_key,
				priv->rss_conf.rss_key_len);
		priv->rss_conf.rss_key_len = rss_conf->rss_key_len;
		priv->rss_conf.rss_hf = rss_conf->rss_hf;
	}

	return ret;
}

static int
xsc_modify_qpn_status(uint32_t qpn, int num, int opcode, struct xsc_dev *xdev)
{
	struct {
		struct xsc_ioctl_data_tl tl;
		struct xsc_ioctl_qp_range info;
	} data_info;

	int ret;

	data_info.tl.opmod = XSC_IOCTL_SET_QP_STATUS;
	data_info.info.opcode = opcode;
	data_info.info.qpn = qpn;
	data_info.info.num = num;

	ret = xsc_ioctl(xdev, XSC_IOCTL_DRV_GET, XSC_IOCTL_SET_QP_STATUS,
			&data_info, sizeof(data_info), NULL, 0);
	if (ret != 0) {
		rte_errno = ret;
		PMD_DRV_LOG(ERR, "modify qp status fail, ret = %d\n", ret);
	}

	return ret;
}

static int
xsc_ethdev_configure(struct rte_eth_dev *dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	int ret;
	struct rte_eth_rss_conf *rss_conf;

	priv->num_sq = dev->data->nb_tx_queues;
	priv->num_rq = dev->data->nb_rx_queues;

	if (dev->data->dev_conf.rxmode.mq_mode & RTE_ETH_MQ_RX_RSS_FLAG)
		dev->data->dev_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_RSS_HASH;

	if (priv->rss_conf.rss_key == NULL) {
		priv->rss_conf.rss_key = rte_zmalloc(NULL, XSC_RSS_HASH_KEY_LEN,
						RTE_CACHE_LINE_SIZE);
		if (priv->rss_conf.rss_key == NULL) {
			PMD_DRV_LOG(ERR, "Failed to alloc rss_key");
			rte_errno = ENOMEM;
			ret = -rte_errno;
			goto error;
		}
		priv->rss_conf.rss_key_len = XSC_RSS_HASH_KEY_LEN;
	}

	if (dev->data->dev_conf.rx_adv_conf.rss_conf.rss_key != NULL) {
		rss_conf = &dev->data->dev_conf.rx_adv_conf.rss_conf;
		ret = xsc_ethdev_rss_hash_update(dev, rss_conf);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Xsc pmd set rss key error!");
			rte_errno = -ENOEXEC;
			goto error;
		}
	}

	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER) {
		PMD_DRV_LOG(ERR, "xsc pmd do not support vlan filter now!");
		rte_errno = EINVAL;
		goto error;
	}

	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP) {
		PMD_DRV_LOG(ERR, "xsc pmd do not support vlan strip now!");
		rte_errno = EINVAL;
		goto error;
	}

	priv->txqs = (void *)dev->data->tx_queues;
	priv->rxqs = (void *)dev->data->rx_queues;
	return 0;

error:
	return -rte_errno;
}

static int
xsc_init_obj(struct xscdv_obj *obj, uint64_t obj_type)
{
#if HAVE_XSC_DV_PROVIDER
	return xscdv_init_obj(obj, obj_type);
#else
	(void)obj;
	(void)obj_type;
	return 0;
#endif
}

static void
xsc_txq_elts_alloc(struct xsc_txq_data *txq_data)
{
	const uint32_t elts_s = 1 << txq_data->elts_n;
	uint32_t i;

	for (i = 0; i < elts_s; ++i)
		txq_data->elts[i] = NULL;
	txq_data->elts_head = 0;
	txq_data->elts_tail = 0;
	txq_data->elts_comp = 0;
}

static void
xsc_txq_elts_free(struct xsc_txq_data *txq_data)
{
	const uint16_t elts_n = 1 << txq_data->elts_n;
	const uint16_t elts_m = elts_n - 1;
	uint16_t elts_head = txq_data->elts_head;
	uint16_t elts_tail = txq_data->elts_tail;
	struct rte_mbuf *(*elts)[elts_n] = &txq_data->elts;

	txq_data->elts_head = 0;
	txq_data->elts_tail = 0;
	txq_data->elts_comp = 0;

	while (elts_tail != elts_head) {
		struct rte_mbuf *elt = (*elts)[elts_tail & elts_m];
		rte_pktmbuf_free_seg(elt);
		++elts_tail;
	}
	PMD_DRV_LOG(DEBUG, "Port %u txq %u free elts", txq_data->port_id, txq_data->idx);
}

static struct ibv_qp *
xsc_txq_ibv_qp_create(struct rte_eth_dev *dev, uint16_t idx)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_txq_data *txq_data = xsc_txq_get(dev, idx);
	struct ibv_qp *qp_obj = NULL;
	struct ibv_qp_init_attr_ex qp_attr = { 0 };
	const int desc = 1 << txq_data->elts_n;
	uint64_t tx_offloads = dev->data->dev_conf.txmode.offloads;

	qp_attr.send_cq = txq_data->cq;
	qp_attr.recv_cq = txq_data->cq;
	qp_attr.cap.max_send_wr = desc;
	qp_attr.cap.max_recv_wr = 0;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.qp_type = IBV_QPT_RAW_PACKET;
	qp_attr.pd = priv->xdev->ibv_pd;
	qp_attr.sq_sig_all = 0;

	if (tx_offloads & (RTE_ETH_TX_OFFLOAD_TCP_TSO)) {
		qp_attr.create_flags = XSC_QP_CREATE_RAWPACKET_TSO;
		qp_attr.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_CREATE_FLAGS;
		txq_data->tso_en = 1;
		PMD_DRV_LOG(DEBUG, "Port %u txq %u, create tso qp",
			dev->data->port_id, idx);
	} else {
		qp_attr.create_flags = XSC_QP_CREATE_RAWPACKET_TX;
		qp_attr.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_CREATE_FLAGS;
		PMD_DRV_LOG(DEBUG, "Port %u txq %u, create non-tso qp",
			dev->data->port_id, idx);
	}

	qp_obj = ibv_create_qp_ex(priv->xdev->ibv_ctx, &qp_attr);
	if (qp_obj == NULL) {
		PMD_DRV_LOG(ERR, "Port %u txq %u, create %s qp fail, errno=%d",
			dev->data->port_id, idx,
			qp_attr.create_flags & XSC_QP_CREATE_RAWPACKET_TSO ?
			"tso" : "non-tso", errno);

		if (!(tx_offloads & (RTE_ETH_TX_OFFLOAD_TCP_TSO))) {
			qp_attr.create_flags = XSC_QP_CREATE_RAWPACKET_TSO;
			qp_attr.comp_mask = IBV_QP_INIT_ATTR_PD |
					    IBV_QP_INIT_ATTR_CREATE_FLAGS;
			PMD_DRV_LOG(DEBUG, "Port %u txq %u, recreate tso qp",
				dev->data->port_id, idx);

			qp_obj = ibv_create_qp_ex(priv->xdev->ibv_ctx, &qp_attr);
			if (qp_obj == NULL)
				PMD_DRV_LOG(ERR, "Port %u txq %u, recreate tso qp fail, errno=%d",
					dev->data->port_id, idx, errno);
			else
				txq_data->tso_en = 1;
		}
	}

	return qp_obj;
}

static int
xsc_txq_ibv_obj_new(struct rte_eth_dev *dev, uint16_t idx)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_txq_data *txq_data = xsc_txq_get(dev, idx);
	struct xsc_hwinfo *hwinfo = &priv->xdev->hwinfo;
	struct xscdv_qp qp_info = { 0 };
	struct xscdv_cq cq_info = { 0 };
	struct xscdv_obj obj;
	const int desc = 1 << txq_data->elts_n;
	uint32_t cqe_n;
	int ret = 0;

	cqe_n = desc;
	txq_data->cq = ibv_create_cq(priv->xdev->ibv_ctx, cqe_n, NULL, NULL, 0);
	if (txq_data->cq == NULL) {
		PMD_DRV_LOG(ERR, "Port %u txq %u, create cq fail",
			dev->data->port_id, idx);
		rte_errno = errno;
		goto error;
	}

	txq_data->qp = xsc_txq_ibv_qp_create(dev, idx);
	if (txq_data->qp == NULL) {
		rte_errno = errno;
		goto error;
	}

	obj.cq.in = txq_data->cq;
	obj.cq.out = &cq_info;
	obj.qp.in = txq_data->qp;
	obj.qp.out = &qp_info;
	ret = xsc_init_obj(&obj, XSCDV_OBJ_CQ | XSCDV_OBJ_QP);
	if (ret != 0) {
		rte_errno = errno;
		goto error;
	}

	txq_data->cqe_n = rte_log2_u32(cq_info.cqe_cnt);
	txq_data->cqe_s = 1 << txq_data->cqe_n;
	txq_data->cqe_m = txq_data->cqe_s - 1;
	txq_data->qpn = ((struct ibv_qp *)txq_data->qp)->qp_num;
	txq_data->wqes = qp_info.sq.buf;
	txq_data->wqe_n = rte_log2_u32(qp_info.sq.wqe_cnt);
	txq_data->wqe_s = 1 << txq_data->wqe_n;
	txq_data->wqe_m = txq_data->wqe_s - 1;
	txq_data->wqe_ds_n = rte_log2_u32(hwinfo->send_seg_num);

	/* txq doobell */
	txq_data->qp_db =  qp_info.sq.db;
	/* cqe doobell */
	txq_data->cq_db = cq_info.db;
	txq_data->cqn = cq_info.cqn;

	txq_data->cqes = (volatile struct xsc_cqe *)cq_info.buf;
	txq_data->cq_ci = 0;
	txq_data->cq_pi = 0;
	txq_data->wqe_ci = 0;
	txq_data->wqe_pi = 0;
	txq_data->wqe_comp = 0;
	xsc_modify_qpn_status(txq_data->qpn, 1, XSC_CMD_OP_RTR2RTS_QP, priv->xdev);
	dev->data->tx_queue_state[idx] = RTE_ETH_QUEUE_STATE_STARTED;

	PMD_DRV_LOG(INFO, "Port %u create tx cq, cqe_s:%d, cqe_n:%d, cq_db=%p, cqn:%d",
		dev->data->port_id,
		txq_data->cqe_s, txq_data->cqe_n,
		txq_data->cq_db, txq_data->cqn);

	PMD_DRV_LOG(INFO, "Port %u create tx qp, wqe_s:%d, wqe_n:%d, qp_db=%p, qpn:%d",
		dev->data->port_id,
		txq_data->wqe_s, txq_data->wqe_n,
		txq_data->qp_db, txq_data->qpn);

	return 0;

error:
	return -rte_errno;
}

static void
xsc_txq_ibv_obj_release(struct xsc_txq_data *txq_data)
{
	PMD_DRV_LOG(DEBUG, "destroy tx queue %u, portid %u\n",
		txq_data->idx, txq_data->port_id);
	if (txq_data->qp != NULL)
		ibv_destroy_qp(txq_data->qp);
	if (txq_data->cq != NULL)
		ibv_destroy_cq(txq_data->cq);
}

static void
xsc_ethdev_txq_release(struct rte_eth_dev *dev, uint16_t idx)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_txq_data *txq_data = xsc_txq_get(dev, idx);

	if (txq_data == NULL)
		return;
	xsc_txq_ibv_obj_release(txq_data);
	if (txq_data->fcqs != NULL)
		rte_free(txq_data->fcqs);
	txq_data->fcqs = NULL;
	xsc_txq_elts_free(txq_data);
	rte_free(txq_data);
	(*priv->txqs)[idx] = NULL;

	dev->data->tx_queues[idx] = NULL;
	dev->data->tx_queue_state[idx] = RTE_ETH_QUEUE_STATE_STOPPED;
}

static int
xsc_txq_start(struct rte_eth_dev *dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_txq_data *txq_data;
	uint16_t i;
	int ret;
	size_t size;

	for (i = 0; i != priv->num_sq; ++i) {
		txq_data = xsc_txq_get(dev, i);
		xsc_txq_elts_alloc(txq_data);
		ret = xsc_txq_ibv_obj_new(dev, i);
		if (ret < 0)
			goto error;

		size = txq_data->cqe_s * sizeof(*txq_data->fcqs);
		txq_data->fcqs = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
		if (!txq_data->fcqs) {
			PMD_DRV_LOG(ERR, "Port %u txq %u alloc fcqs memory failed",
				dev->data->port_id, i);
			rte_errno = ENOMEM;
			goto error;
		}
	}

	return 0;

error:
	/* Queue resources are released by xsc_ethdev_start calling the stop interface */
	return -rte_errno;
}

static int
xsc_rxq_elts_alloc(struct xsc_rxq_data *rxq_data)
{
	uint32_t elts_s = rxq_data->wqe_s;
	struct rte_mbuf *mbuf;
	uint32_t i;

	for (i = 0; (i != elts_s); ++i) {
		mbuf = rte_pktmbuf_alloc(rxq_data->mp);
		if (mbuf == NULL) {
			PMD_DRV_LOG(ERR, "Port %u rxq %u empty mbuf pool",
				rxq_data->port_id, rxq_data->idx);
			rte_errno = ENOMEM;
			goto error;
		}

		mbuf->port = rxq_data->port_id;
		mbuf->nb_segs = 1;
		rte_pktmbuf_data_len(mbuf) = rte_pktmbuf_data_room_size(rxq_data->mp);
		rte_pktmbuf_pkt_len(mbuf) = rte_pktmbuf_data_room_size(rxq_data->mp);
		(*rxq_data->elts)[i] = mbuf;
	}

	return 0;
error:
	elts_s = i;
	for (i = 0; (i != elts_s); ++i) {
		if ((*rxq_data->elts)[i] != NULL)
			rte_pktmbuf_free_seg((*rxq_data->elts)[i]);
		(*rxq_data->elts)[i] = NULL;
	}

	PMD_DRV_LOG(ERR, "Port %u rxq %u start failed, free elts",
		rxq_data->port_id, rxq_data->idx);

	return -rte_errno;
}

static void
xsc_rxq_elts_free(struct xsc_rxq_data *rxq_data)
{
	uint16_t i;

	if (rxq_data->elts == NULL)
		return;
	for (i = 0; i != rxq_data->wqe_s; ++i) {
		if ((*rxq_data->elts)[i] != NULL)
			rte_pktmbuf_free_seg((*rxq_data->elts)[i]);
		(*rxq_data->elts)[i] = NULL;
	}

	PMD_DRV_LOG(DEBUG, "Port %u rxq %u free elts", rxq_data->port_id, rxq_data->idx);
}

static void
xsc_rxq_rss_obj_release(struct xsc_ethdev_priv *priv, struct xsc_rxq_data *rxq_data)
{
	struct xsc_destroy_qp_mbox_in in = { .hdr = { 0 } };
	struct xsc_destroy_qp_mbox_out out = { .hdr = { 0 } };
	int ret, in_len, out_len;
	uint32_t qpn = rxq_data->qpn;

	xsc_modify_qpn_status(qpn, 1, XSC_CMD_OP_QP_2RST, priv->xdev);

	in_len = sizeof(struct xsc_destroy_qp_mbox_in);
	out_len = sizeof(struct xsc_destroy_qp_mbox_out);
	in.hdr.opcode = rte_cpu_to_be_16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = rte_cpu_to_be_32(rxq_data->qpn);

	ret = xsc_mailbox_exec(priv->xdev, &in, in_len, &out, out_len);
	if (ret != 0 || out.hdr.status != 0) {
		PMD_DRV_LOG(ERR, "release rss rq failed, port id=%d, "
			"qid=%d, err=%d, out.status=%u\n",
			rxq_data->port_id, rxq_data->idx, ret, out.hdr.status);
		rte_errno = ENOEXEC;
		return;
	}

	if (rxq_data->rq_pas != NULL)
		rte_memzone_free(rxq_data->rq_pas);

	if (rxq_data->cq != NULL)
		ibv_destroy_cq(rxq_data->cq);
	rxq_data->cq = NULL;
}

static void
xsc_ethdev_rxq_release(struct rte_eth_dev *dev, uint16_t idx)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_rxq_data *rxq_data = xsc_rxq_get(dev, idx);

	if (rxq_data == NULL)
		return;
	xsc_rxq_rss_obj_release(priv, rxq_data);
	xsc_rxq_elts_free(rxq_data);
	rte_free(rxq_data);
	(*priv->rxqs)[idx] = NULL;

	dev->data->rx_queues[idx] = NULL;
	dev->data->rx_queue_state[idx] = RTE_ETH_QUEUE_STATE_STOPPED;
}

static void
xsc_rxq_initialize(struct xsc_ethdev_priv *priv, struct xsc_rxq_data *rxq_data)
{
	const uint32_t wqe_n = rxq_data->wqe_s;
	uint32_t i;
	uint32_t seg_len = 0;
	struct xsc_hwinfo *hwinfo = &priv->xdev->hwinfo;
	uint32_t rx_ds_num = hwinfo->recv_seg_num;
	uint32_t log2ds = rte_log2_u32(rx_ds_num);
	uintptr_t addr;
	struct rte_mbuf *mbuf;
	volatile struct xsc_wqe_data_seg *seg;

	for (i = 0; (i != wqe_n); ++i) {
		mbuf = (*rxq_data->elts)[i];
		seg = &((volatile struct xsc_wqe_data_seg *)rxq_data->wqes)[i * rx_ds_num];
		addr = (uintptr_t)rte_pktmbuf_iova(mbuf);
		seg_len = rte_pktmbuf_data_len(mbuf);
		*seg = (struct xsc_wqe_data_seg){
			.va = rte_cpu_to_le_64(addr),
			.seg_len = rte_cpu_to_le_32(seg_len),
			.lkey = 0,
		};
	}

	rxq_data->rq_ci = wqe_n;
	rxq_data->sge_n = rte_log2_u32(rx_ds_num);

	rte_io_wmb();
	union xsc_recv_doorbell recv_db = {
		.recv_data = 0
	};

	recv_db.next_pid = wqe_n << log2ds;
	recv_db.qp_num = rxq_data->qpn;
	*rxq_data->rq_db = rte_cpu_to_le_32(recv_db.recv_data);
}

static int
xsc_rxq_rss_qp_create(struct rte_eth_dev *dev)
{
	struct xsc_create_multiqp_mbox_in *in;
	struct xsc_create_qp_request *req;
	struct xsc_create_multiqp_mbox_out *out;
	uint8_t log_ele;
	uint64_t iova;
	int wqe_n;
	int in_len, out_len, cmd_len;
	int entry_total_len, entry_len;
	uint8_t log_rq_sz, log_sq_sz = 0;
	int j, ret;
	uint16_t i, pa_num;
	int rqn_base;
	size_t page_size = PAGE_SIZE;
	struct xsc_rxq_data *rxq_data;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_hwinfo *hwinfo = &priv->xdev->hwinfo;
	int port_id = dev->data->port_id;
	char name[64] = { 0 };

	/* paslen */
	rxq_data = xsc_rxq_get(dev, 0);
	log_ele = rte_log2_u32(sizeof(struct xsc_wqe_data_seg));
	wqe_n = rxq_data->wqe_s;
	log_rq_sz = rte_log2_u32(wqe_n * hwinfo->recv_seg_num);

	pa_num = XSC_DIV_ROUND_UP((1 << (log_rq_sz + log_sq_sz + log_ele)), page_size);
	entry_len = sizeof(struct xsc_create_qp_request) +
			sizeof(uint64_t) * pa_num;
	entry_total_len = entry_len * priv->num_rq;

	in_len = sizeof(struct xsc_create_multiqp_mbox_in) + entry_total_len;
	out_len = sizeof(struct xsc_create_multiqp_mbox_out) + entry_total_len;
	cmd_len = RTE_MAX(in_len, out_len);
	in = rte_zmalloc(NULL, cmd_len, RTE_CACHE_LINE_SIZE);
	if (in == NULL) {
		rte_errno = ENOMEM;
		PMD_DRV_LOG(ERR, "Alloc rss qp create cmd memory failed\n");
		goto error;
	}

	in->qp_num = rte_cpu_to_be_16((uint16_t)priv->num_rq);
	in->qp_type = XSC_QUEUE_TYPE_RAW;
	in->req_len = rte_cpu_to_be_32(cmd_len);

	for (i = 0; i < priv->num_rq; i++) {
		rxq_data = (*priv->rxqs)[i];
		req = (struct xsc_create_qp_request *)(&in->data[0] + entry_len * i);
		req->input_qpn = rte_cpu_to_be_16(0); /* useless for eth */
		req->pa_num = rte_cpu_to_be_16(pa_num);
		req->qp_type = XSC_QUEUE_TYPE_RAW;
		req->log_rq_sz = log_rq_sz;
		req->cqn_recv = rte_cpu_to_be_16((uint16_t)rxq_data->cqn);
		req->cqn_send = req->cqn_recv;
		req->glb_funcid = rte_cpu_to_be_16((uint16_t)hwinfo->func_id);
		/* alloc pas addr */
		sprintf(name, "wqe_mem_rx_%d_%d", port_id, i);
		rxq_data->rq_pas = rte_memzone_reserve_aligned(name,
				(page_size * pa_num), SOCKET_ID_ANY, 0, page_size);
		if (rxq_data->rq_pas == NULL) {
			rte_errno = ENOMEM;
			PMD_DRV_LOG(ERR, "Alloc rxq pas memory failed\n");
			goto error;
		}

		iova = rxq_data->rq_pas->iova;
		for (j = 0; j < pa_num; j++)
			req->pas[j] = rte_cpu_to_be_64(iova + j * page_size);
	}

	in->hdr.opcode = rte_cpu_to_be_16(XSC_CMD_OP_CREATE_MULTI_QP);
	out = (struct xsc_create_multiqp_mbox_out *)in;
	ret = xsc_mailbox_exec(priv->xdev, in, in_len, out, out_len);
	if (ret != 0 || out->hdr.status != 0) {
		PMD_DRV_LOG(ERR, "Create rss rq failed, port id=%d, "
			"qp_num=%d, type=%d, err=%d, out.status=%u\n",
			port_id, priv->num_rq, XSC_QUEUE_TYPE_RAW, ret, out->hdr.status);
		rte_errno = ENOEXEC;
		goto error;
	}
	rqn_base = rte_be_to_cpu_32(out->qpn_base) & 0xffffff;

	for (i = 0; i < priv->num_rq; i++) {
		rxq_data = xsc_rxq_get(dev, i);
		rxq_data->wqes = rxq_data->rq_pas->addr;
		rxq_data->rq_db = (uint32_t *)((uint8_t *)priv->xdev->bar_addr +
					XSC_RXQ_DB_PF_OFFSET);
		rxq_data->qpn = rqn_base + i;
		xsc_modify_qpn_status(rxq_data->qpn, 1, XSC_CMD_OP_RTR2RTS_QP,
				      priv->xdev);
		xsc_rxq_initialize(priv, rxq_data);
		rxq_data->cq_ci = 0;
		priv->dev_data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
		PMD_DRV_LOG(INFO, "Port %u create rx qp, wqe_s:%d, wqe_n:%d, qp_db=%p, qpn:%d",
			dev->data->port_id,
			rxq_data->wqe_s, rxq_data->wqe_n,
			rxq_data->rq_db, rxq_data->qpn);
	}

	if (in != NULL)
		rte_free(in);
	return 0;

error:
	if (in != NULL)
		rte_free(in);
	return -rte_errno;
}

static int
xsc_rxq_rss_obj_new(struct rte_eth_dev *dev)
{
	int ret;
	uint32_t i;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	uint16_t port_id = priv->dev_data->port_id;
	struct xsc_rxq_data *rxq_data;
	struct xscdv_cq cq_info = { 0 };
	struct xscdv_obj obj;
	uint32_t cqe_s;

	/* Create CQ */
	for (i = 0; i < priv->num_rq; ++i) {
		rxq_data = xsc_rxq_get(dev, i);
		cqe_s = rxq_data->wqe_s;
		rxq_data->cq = ibv_create_cq(priv->xdev->ibv_ctx, cqe_s, NULL, NULL, 0);
		if (rxq_data->cq == NULL) {
			PMD_DRV_LOG(ERR, "Port %u rxq %u create cq fail", port_id, i);
			rte_errno = errno;
			goto error;
		}
		obj.cq.in = rxq_data->cq;
		obj.cq.out = &cq_info;
		ret = xsc_init_obj(&obj, XSCDV_OBJ_CQ);
		if (ret) {
			rte_errno = errno;
			goto error;
		}

		rxq_data->cqe_n = rte_log2_u32(cq_info.cqe_cnt);
		rxq_data->cqe_s = 1 << rxq_data->cqe_n;
		rxq_data->cqe_m = rxq_data->cqe_s - 1;
		rxq_data->cqes = (volatile struct xsc_cqe (*)[])(uintptr_t)cq_info.buf;
		rxq_data->cq_db = cq_info.db;
		rxq_data->cqn = cq_info.cqn;
		PMD_DRV_LOG(INFO, "Port %u create rx cq, cqe_s:%d, cqe_n:%d, cq_db=%p, cqn:%d",
			dev->data->port_id,
			rxq_data->cqe_s, rxq_data->cqe_n,
			rxq_data->cq_db, rxq_data->cqn);
	}

	ret = xsc_rxq_rss_qp_create(dev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Port %u rss rxq create fail", port_id);
		goto error;
	}
	return 0;

error:
	return -rte_errno;
}

static void
xsc_txq_stop(struct rte_eth_dev *dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	uint16_t i;

	for (i = 0; i != priv->num_sq; ++i)
		xsc_ethdev_txq_release(dev, i);
	priv->txqs = NULL;
}

static void
xsc_rxq_stop(struct rte_eth_dev *dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	uint16_t i;

	for (i = 0; i != priv->num_rq; ++i)
		xsc_ethdev_rxq_release(dev, i);
	priv->rxqs = NULL;
}

static int
xsc_rxq_start(struct rte_eth_dev *dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_rxq_data *rxq_data;
	uint16_t i;
	int ret;

	for (i = 0; i != priv->num_rq; ++i) {
		rxq_data = xsc_rxq_get(dev, i);
		if (dev->data->rx_queue_state[i] != RTE_ETH_QUEUE_STATE_STARTED) {
			ret = xsc_rxq_elts_alloc(rxq_data);
			if (ret != 0)
				goto error;
		}
	}

	ret = xsc_rxq_rss_obj_new(dev);
	if (ret != 0)
		goto error;

	return 0;
error:
	/* Queue resources are released by xsc_ethdev_start calling the stop interface */
	return -rte_errno;
}

static int
xsc_ethdev_start(struct rte_eth_dev *dev)
{
	int ret;

	ret = xsc_txq_start(dev);
	if (ret) {
		PMD_DRV_LOG(ERR, "Port %u txq start failed: %s",
			dev->data->port_id, strerror(rte_errno));
		goto error;
	}

	ret = xsc_rxq_start(dev);
	if (ret) {
		PMD_DRV_LOG(ERR, "Port %u Rx queue start failed: %s",
			dev->data->port_id, strerror(rte_errno));
		goto error;
	}

	dev->data->dev_started = 1;

	rte_wmb();
	dev->rx_pkt_burst = xsc_rx_burst;
	dev->tx_pkt_burst = xsc_tx_burst;

	return 0;

error:
	dev->data->dev_started = 0;
	xsc_txq_stop(dev);
	xsc_rxq_stop(dev);
	return -rte_errno;
}

static int
xsc_ethdev_stop(struct rte_eth_dev *dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	uint16_t i;

	PMD_DRV_LOG(DEBUG, "Port %u stopping", dev->data->port_id);
	dev->data->dev_started = 0;
	dev->rx_pkt_burst = rte_eth_pkt_burst_dummy;
	dev->tx_pkt_burst = rte_eth_pkt_burst_dummy;
	rte_wmb();

	rte_delay_us_sleep(1000 * priv->num_rq);
	for (i = 0; i < priv->num_rq; ++i)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < priv->num_sq; ++i)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}

static int
xsc_ethdev_close(struct rte_eth_dev *dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	PMD_DRV_LOG(DEBUG, "Port %u closing", dev->data->port_id);
	dev->rx_pkt_burst = rte_eth_pkt_burst_dummy;
	dev->tx_pkt_burst = rte_eth_pkt_burst_dummy;
	rte_wmb();

	rte_delay_us_sleep(1000);
	xsc_txq_stop(dev);
	rte_delay_us_sleep(1000);
	xsc_rxq_stop(dev);

	if (priv->rss_conf.rss_key != NULL)
		rte_free(priv->rss_conf.rss_key);

	/* priv is released in rte_eth_dev_release_port */

	dev->data->mac_addrs = NULL;
	return 0;
}

static int
xsc_ethdev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
			  uint32_t socket, const struct rte_eth_rxconf *conf,
			  struct rte_mempool *mp)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_rxq_data *rxq_data = NULL;
	uint16_t desc_n;
	uint16_t rx_free_thresh;
	uint64_t offloads = conf->offloads |
			    dev->data->dev_conf.rxmode.offloads;

	desc = (desc > XSC_MAX_DESC_NUMBER) ? XSC_MAX_DESC_NUMBER : desc;
	desc_n = desc;

	if (!rte_is_power_of_2(desc))
		desc_n = 1 << rte_log2_u32(desc);

	rxq_data = rte_malloc_socket(NULL, sizeof(*rxq_data) + desc_n * sizeof(struct rte_mbuf *),
					RTE_CACHE_LINE_SIZE, socket);
	if (rxq_data == NULL) {
		PMD_DRV_LOG(ERR, "Port %u create rxq idx %d failure",
				dev->data->port_id, idx);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	rxq_data->idx = idx;
	rxq_data->priv = priv;
	(*priv->rxqs)[idx] = rxq_data;

	rx_free_thresh = (conf->rx_free_thresh) ? conf->rx_free_thresh : XSC_RX_FREE_THRESH;
	rxq_data->rx_free_thresh = rx_free_thresh;

	rxq_data->elts = (struct rte_mbuf *(*)[desc_n])(rxq_data + 1);
	rxq_data->mp = mp;
	rxq_data->socket = socket;

	rxq_data->csum = !!(offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM);
	rxq_data->hw_timestamp = !!(offloads & RTE_ETH_RX_OFFLOAD_TIMESTAMP);
	rxq_data->crc_present = 0;

	rxq_data->wqe_n = rte_log2_u32(desc_n);
	rxq_data->wqe_s = desc_n;
	rxq_data->wqe_m = desc_n - 1;

	dev->data->rx_queues[idx] = rxq_data;
	return 0;
}

static int
xsc_ethdev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
			  uint32_t socket, const struct rte_eth_txconf *conf)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_txq_data *txq;
	uint16_t desc_n;

	desc = (desc > XSC_MAX_DESC_NUMBER) ? XSC_MAX_DESC_NUMBER : desc;
	desc_n = desc;

	if (!rte_is_power_of_2(desc))
		desc_n = 1 << rte_log2_u32(desc);

	txq = rte_malloc_socket(NULL, sizeof(*txq) + desc_n * sizeof(struct rte_mbuf *),
					RTE_CACHE_LINE_SIZE, socket);
	txq->offloads = conf->offloads | dev->data->dev_conf.txmode.offloads;
	txq->priv = priv;
	txq->socket = socket;

	txq->elts_n = rte_log2_u32(desc_n);
	txq->elts_s = desc_n;
	txq->elts_m = desc_n - 1;
	txq->port_id = dev->data->port_id;
	txq->idx = idx;

	(*priv->txqs)[idx] = txq;
	return 0;
}

static int
xsc_ethdev_link_update(__rte_unused struct rte_eth_dev *dev,
		       __rte_unused int wait_to_complete)
{
	return 0;
}

const struct eth_dev_ops xsc_dev_ops = {
	.dev_configure = xsc_ethdev_configure,
	.dev_start = xsc_ethdev_start,
	.dev_stop = xsc_ethdev_stop,
	.dev_close = xsc_ethdev_close,
	.link_update = xsc_ethdev_link_update,
	.rx_queue_setup = xsc_ethdev_rx_queue_setup,
	.tx_queue_setup = xsc_ethdev_tx_queue_setup,
	.rx_queue_release = xsc_ethdev_rxq_release,
	.tx_queue_release = xsc_ethdev_txq_release,
	.rss_hash_update = xsc_ethdev_rss_hash_update,
	.rss_hash_conf_get = xsc_ethdev_rss_hash_conf_get,
};

static int
xsc_ethdev_init_one_representor(struct rte_eth_dev *eth_dev, void *init_params)
{
	struct xsc_repr_port *repr_port = (struct xsc_repr_port *)init_params;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(eth_dev);
	struct xsc_dev_config *config = &priv->config;
	struct rte_ether_addr mac;

	priv->repr_port = repr_port;
	repr_port->drv_data = eth_dev;
	priv->xdev = repr_port->xdev;
	priv->mtu = RTE_ETHER_MTU;
	priv->funcid_type = (repr_port->info.funcid & FUNCID_TYPE_MASK) >> 14;
	priv->funcid = repr_port->info.funcid & FUNCID_MASK;
	if (repr_port->info.port_type == XSC_PORT_TYPE_UPLINK ||
		repr_port->info.port_type == XSC_PORT_TYPE_UPLINK_BOND)
		priv->eth_type = RTE_ETH_REPRESENTOR_PF;
	else
		priv->eth_type = RTE_ETH_REPRESENTOR_VF;
	priv->representor_id = repr_port->info.repr_id;
	priv->dev_data = eth_dev->data;
	priv->ifindex = repr_port->info.ifindex;

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
	eth_dev->data->mac_addrs = priv->mac;
	if (rte_is_zero_ether_addr(eth_dev->data->mac_addrs)) {
		if (priv->ifindex > 0) {
			int ret  = xsc_get_mac(mac.addr_bytes, priv->ifindex);
			if (ret != 0) {
				PMD_DRV_LOG(ERR, "port %u cannot get MAC address",
						eth_dev->data->port_id);
				return -ENODEV;
			}
		} else {
			rte_eth_random_addr(mac.addr_bytes);
		}
	}

	xsc_mac_addr_add(eth_dev, &mac, 0);

	if (priv->ifindex > 0)
		xsc_get_mtu(&priv->mtu, priv->ifindex);

	config->hw_csum = 1;

	config->pph_flag =  priv->xdev->devargs.pph_mode;
	if ((config->pph_flag & XSC_TX_PPH) != 0) {
		config->tso = 0;
	} else {
		config->tso = 1;
		if (config->tso)
			config->tso_max_payload_sz = 1500;
	}

	priv->representor = !!priv->eth_type;
	if (priv->representor) {
		eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
		eth_dev->data->representor_id = priv->representor_id;
		eth_dev->data->backer_port_id = eth_dev->data->port_id;
	}
	eth_dev->dev_ops = &xsc_dev_ops;

	eth_dev->rx_pkt_burst = rte_eth_pkt_burst_dummy;
	eth_dev->tx_pkt_burst = rte_eth_pkt_burst_dummy;

	rte_eth_dev_probing_finish(eth_dev);

	return 0;
}

static int
xsc_ethdev_init_representors(struct rte_eth_dev *eth_dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(eth_dev);
	struct rte_eth_devargs eth_da = { .nb_representor_ports = 0 };
	struct rte_device *dev;
	struct xsc_dev *xdev;
	struct xsc_repr_port *repr_port;
	char name[RTE_ETH_NAME_MAX_LEN];
	int i;
	int ret;

	PMD_INIT_FUNC_TRACE();

	dev = &priv->pci_dev->device;
	if (dev->devargs != NULL) {
		ret = rte_eth_devargs_parse(dev->devargs->args, &eth_da, 1);
		if (ret < 0) {
			PMD_DRV_LOG(ERR, "Failed to parse device arguments: %s",
				    dev->devargs->args);
			return -EINVAL;
		}
	}

	xdev = priv->xdev;
	ret = xsc_repr_ports_probe(xdev, eth_da.nb_representor_ports, RTE_MAX_ETHPORTS);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to probe %d xsc device representors",
			    eth_da.nb_representor_ports);
		return ret;
	}

	repr_port = &xdev->repr_ports[XSC_DEV_REPR_PORT];
	ret = xsc_ethdev_init_one_representor(eth_dev, repr_port);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to init backing representor");
		return ret;
	}

	for (i = 1; i < xdev->num_repr_ports; i++) {
		repr_port = &xdev->repr_ports[i];
		snprintf(name, sizeof(name), "%s_rep_%d",
			 xdev->ibv_name, repr_port->info.repr_id);
		ret = rte_eth_dev_create(&xdev->pci_dev->device,
					 name,
					 sizeof(struct xsc_ethdev_priv),
					 NULL, NULL,
					 xsc_ethdev_init_one_representor,
					 repr_port);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to create representor: %d", i);
			goto destroy_reprs;
		}
	}

	return 0;

destroy_reprs:
	while ((i--) > 1) {
		repr_port = &xdev->repr_ports[i];
		rte_eth_dev_destroy((struct rte_eth_dev *)repr_port->drv_data, NULL);
	}
	return ret;
}

static int
xsc_ethdev_init(struct rte_eth_dev *eth_dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(eth_dev);
	int ret;

	PMD_INIT_FUNC_TRACE();

	priv->eth_dev = eth_dev;
	priv->pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	ret = xsc_dev_init(priv->pci_dev, &priv->xdev);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to initialize xsc device");
		return ret;
	}

	ret = xsc_ethdev_init_representors(eth_dev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize representors");
		goto uninit_xsc_dev;
	}

	return 0;

uninit_xsc_dev:
	xsc_dev_uninit(priv->xdev);
	return ret;
}

static int
xsc_ethdev_uninit(struct rte_eth_dev *eth_dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(eth_dev);

	PMD_INIT_FUNC_TRACE();

	xsc_dev_uninit(priv->xdev);

	return 0;
}

static int
xsc_ethdev_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		     struct rte_pci_device *pci_dev)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = rte_eth_dev_pci_generic_probe(pci_dev,
					    sizeof(struct xsc_ethdev_priv),
					    xsc_ethdev_init);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to probe ethdev: %s", pci_dev->name);
		return ret;
	}

	return 0;
}

static int
xsc_ethdev_pci_remove(struct rte_pci_device *pci_dev)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = rte_eth_dev_pci_generic_remove(pci_dev, xsc_ethdev_uninit);
	if (ret) {
		PMD_DRV_LOG(ERR, "Could not remove ethdev: %s", pci_dev->name);
		return ret;
	}

	return 0;
}

static const struct rte_pci_id xsc_ethdev_pci_id_map[] = {
	{ RTE_PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_PCI_DEV_ID_MS) },
};

static struct rte_pci_driver xsc_ethdev_pci_driver = {
	.id_table  = xsc_ethdev_pci_id_map,
	.probe = xsc_ethdev_pci_probe,
	.remove = xsc_ethdev_pci_remove,
};

RTE_INIT(xsc_pmd_init)
{
	ibv_fork_init();
}

RTE_PMD_REGISTER_PCI(net_xsc, xsc_ethdev_pci_driver);
RTE_PMD_REGISTER_PCI_TABLE(net_xsc, xsc_ethdev_pci_id_map);
RTE_PMD_REGISTER_PARAM_STRING(net_xsc,
			      XSC_PPH_MODE_ARG "=<x>"
			      XSC_NIC_MODE_ARG "=<x>"
			      XSC_FLOW_MODE_ARG "=<x>");

RTE_LOG_REGISTER_SUFFIX(xsc_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_driver, driver, NOTICE);
#ifdef RTE_ETHDEV_DEBUG_RX
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_rx, rx, DEBUG);
#endif
#ifdef RTE_ETHDEV_DEBUG_TX
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_tx, tx, DEBUG);
#endif
