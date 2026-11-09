/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2026 Altera Corporation
 */

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_memzone.h>

#include "mcdma_eth.h"

static int mcdma_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t qid);
static int mcdma_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t qid);

static uint16_t
mcdma_dev_mtu_get(const struct rte_eth_dev *dev)
{
	if (dev->data->dev_conf.rxmode.mtu != 0)
		return dev->data->dev_conf.rxmode.mtu;
	if (dev->data->mtu != 0)
		return dev->data->mtu;

	return RTE_ETHER_MTU;
}

static uint32_t
mcdma_rx_frame_len_from_mtu(uint16_t mtu)
{
	return (uint32_t)mtu + MCDMA_RX_ETH_OVERHEAD;
}

static int
mcdma_rx_frame_len_check(struct rte_eth_dev *dev, uint32_t frame_len)
{
	if (frame_len == 0 || frame_len > MCDMA_MAX_RX_FRAME_LEN) {
		PMD_DRV_LOG(ERR,
			    "port %u: Rx frame length %u invalid (HW max %u)",
			    dev->data->port_id, frame_len,
			    MCDMA_MAX_RX_FRAME_LEN);
		return -EINVAL;
	}

	return 0;
}

static int
mcdma_rx_seg_len_for_pool(struct rte_eth_dev *dev, struct rte_mempool *mb_pool,
			   uint32_t *rx_seg_len)
{
	uint32_t frame_len = mcdma_rx_frame_len_from_mtu(mcdma_dev_mtu_get(dev));
	uint32_t buf_len = rte_pktmbuf_data_room_size(mb_pool);
	int ret;

	ret = mcdma_rx_frame_len_check(dev, frame_len);
	if (ret != 0)
		return ret;

	if (buf_len <= RTE_PKTMBUF_HEADROOM) {
		PMD_DRV_LOG(ERR, "port %u: mbuf pool data room %u too small",
			    dev->data->port_id, buf_len);
		return -EINVAL;
	}

	buf_len -= RTE_PKTMBUF_HEADROOM;
	if (frame_len > buf_len) {
		PMD_DRV_LOG(ERR,
			    "port %u: Rx frame %u B exceeds mbuf data room %u B (MTU %u)",
			    dev->data->port_id, frame_len, buf_len,
			    mcdma_dev_mtu_get(dev));
		return -EINVAL;
	}

	*rx_seg_len = frame_len;
	return 0;
}

static int mcdma_wait_queue_drain(struct mcdma_queue *q)
{
	uint32_t retry;

	for (retry = 0; retry < MCDMA_CNT_HEAD_MOVE; retry++) {
		rte_rmb();
		if (q->cons_didx == q->prod_didx)
			return 0;
		rte_delay_us_block(10);
	}

	PMD_DRV_LOG(ERR,
		    "queue %u drain timeout (cons_didx=%u prod_didx=%u)",
		    q->qid, q->cons_didx, q->prod_didx);
	return -ETIMEDOUT;
}

/* Free mbufs still held between freed_cons_didx and prod_didx */
static void
mcdma_sw_ring_free_inflight(struct mcdma_queue *q)
{
	uint16_t nb_to_free;

	nb_to_free = MCDMA_RING_USED_COUNT(mcdma_queue_prod_ring(q),
				      mcdma_queue_freed_ring(q), q->num_descs);
	while (nb_to_free--) {
		struct mcdma_desc *d;
		uint16_t idx = MCDMA_NEXT_IDX(mcdma_queue_freed_ring(q), q->num_descs);
		d = MCDMA_DESC_PTR(q, idx);
		if (q->sw_ring[idx] != NULL &&
		    (q->dir != MCDMA_DIR_H2D || d->eof))
			rte_pktmbuf_free(q->sw_ring[idx]);
		q->sw_ring[idx] = NULL;
		q->freed_cons_didx = d->didx;
	}
}

/* Caller to ensure value fits inside the mask */
static int mcdma_reg_write_verify(struct mcdma_queue *q, uint32_t reg,
			       uint32_t mask, uint32_t val, unsigned int shift,
			       uint64_t timeout_us, uint32_t poll_val)
{
	uint32_t reg_val;
	uint64_t start_tsc;
	uint64_t timeout_tsc;

	if (!mask)
		return -EINVAL;

	reg_val = mcdma_qcsr_reg_readl(q->qcsr, reg);
	reg_val = (reg_val & ~mask) | ((val << shift) & mask);
	mcdma_qcsr_reg_writel(q->qcsr, reg, reg_val);

	start_tsc = rte_get_timer_cycles();
	timeout_tsc = (timeout_us * rte_get_timer_hz()) / 1000000;

	for (;;) {
		uint32_t readback = mcdma_qcsr_reg_readl(q->qcsr, reg);
		if (((readback & mask) >> shift) == poll_val)
			return 0;

		if (rte_get_timer_cycles() - start_tsc >= timeout_tsc)
			return -ETIMEDOUT;

		rte_delay_us_block(10);
	}
}

static void mcdma_dev_descq_disable(struct mcdma_queue *q)
{
	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_CTRL, 0);
}

static void mcdma_dev_descq_free(struct mcdma_queue *q)
{
	const struct rte_memzone *qzone;
	char z_name[RTE_MEMZONE_NAMESIZE];
	const char *ring_name = (q->dir == MCDMA_DIR_H2D) ?
				MCDMA_TX_MZONE_NAME : MCDMA_RX_MZONE_NAME;
	struct rte_eth_dev *dev = q->ethdev;

	snprintf(z_name, sizeof(z_name), "%s%s%u_%u",
		 dev->device->driver->name, ring_name,
		 dev->data->port_id, q->qid);

	qzone = rte_memzone_lookup(z_name);
	if (qzone)
		rte_memzone_free(qzone);

	rte_free(q->sw_ring);
}

/* Allocate and initialize software queue structure */
static int mcdma_sw_descq_alloc(struct rte_eth_dev *dev, struct mcdma_queue **q_ptr,
				uint32_t dir, uint16_t q_id, uint16_t nb_desc,
				unsigned int socket_id)
{
	struct mcdma_pci_device *mcdma_dev = dev->data->dev_private;
	struct mcdma_queue *q;
	const char *type = (dir == MCDMA_DIR_H2D) ? "MCDMA_TxQ" : "MCDMA_RxQ";
	uint32_t qcsr_offset = (dir == MCDMA_DIR_H2D) ?
			       (MCDMA_QCSR_H2D_OFFSET + (q_id * MCDMA_QCSR_SIZE)) :
			       (q_id * MCDMA_QCSR_SIZE);

	if (nb_desc == 0 || nb_desc > MCDMA_MAX_RING_DESCS ||
	    (nb_desc % MCDMA_NUM_DESC_PER_PAGE) != 0 ||
	    !rte_is_power_of_2(nb_desc)) {
		PMD_DRV_LOG(ERR,
			    "Invalid descriptor ring size %u (power of 2, align %u, max %u)",
			    nb_desc, MCDMA_NUM_DESC_PER_PAGE, MCDMA_MAX_RING_DESCS);
		return -EINVAL;
	}

	q = rte_zmalloc_socket(type, sizeof(*q), RTE_CACHE_LINE_SIZE, socket_id);
	if (!q) {
		PMD_DRV_LOG(ERR, "Failed to allocate %s queue", type);
		return -ENOMEM;
	}

	*q_ptr = q;

	q->socket_id = (int)socket_id;
	q->qcsr = (uint8_t *)mcdma_get_csraddr(mcdma_dev->bar_base,
					       MCDMA_CONFIG_QCSR) + qcsr_offset;
	q->qid = q_id;
	q->ethdev = dev;
	q->dir = dir;
	q->num_descs = nb_desc;
	q->num_desc_pages = (nb_desc * MCDMA_DESC_LEN) / MCDMA_DESC_PAGE_SIZE;

	q->sw_ring = rte_zmalloc_socket("desc_sw_ctx",
					q->num_descs * sizeof(struct rte_mbuf *), 0,
					socket_id);
	if (!q->sw_ring) {
		PMD_DRV_LOG(ERR, "Failed to allocate sw ring");
		rte_free(q);
		return -ENOMEM;
	}

	return 0;
}

/* Allocate HW descriptor ring */
static int mcdma_dev_descq_alloc(struct rte_eth_dev *dev,
				 struct mcdma_queue *q)
{
	const struct rte_memzone *qzone;
	struct mcdma_desc *desc;
	size_t len = MCDMA_DESC_PAGE_SIZE * q->num_desc_pages;
	char z_name[RTE_MEMZONE_NAMESIZE];
	const char *ring_name = (q->dir == MCDMA_DIR_H2D) ?
				MCDMA_TX_MZONE_NAME : MCDMA_RX_MZONE_NAME;
	unsigned int flags = RTE_MEMZONE_IOVA_CONTIG |
			     RTE_MEMZONE_2MB |
			     RTE_MEMZONE_SIZE_HINT_ONLY;
	uint32_t i;

	snprintf(z_name, sizeof(z_name), "%s%s%u_%u",
		 dev->device->driver->name, ring_name,
		 dev->data->port_id, q->qid);

	qzone = rte_memzone_reserve_bounded(z_name, len, q->socket_id,
					    flags, RTE_CACHE_LINE_SIZE, len);
	if (!qzone) {
		PMD_DRV_LOG(ERR,
			    "qbuf zone allocation failed with err: %s name: %s len: %zu",
			    rte_strerror(rte_errno), z_name, len);
		return -rte_errno;
	}

	if (qzone->iova == RTE_BAD_IOVA) {
		PMD_DRV_LOG(ERR, "qbuf IOVA mapping failure");
		return -EIO;
	}

	q->qbuf = qzone->addr;
	memset(q->qbuf, 0, len);
	/* VFIO mode */
	q->qbuf_dma = rte_mem_virt2iova(q->qbuf);
	desc = (struct mcdma_desc *)q->qbuf;

	/* Initialize link bit of all descs to zero */
	for (i = 0; i < q->num_descs; i++)
		desc[i].link = 0;

	/* For every desc at the page boundary src points to the addrss of next desc */
	for (i = MCDMA_NUM_DESC_PER_PAGE; i <= q->num_descs; i += MCDMA_NUM_DESC_PER_PAGE) {
		desc[i - 1].link = 1;
		/*
		 * src for last descriptor points the address for desc ring,
		 * else next page
		 */
		desc[i - 1].src = (i == q->num_descs) ?
			rte_mem_virt2iova(q->qbuf) : rte_mem_virt2iova(desc + i);
	}

	q->wbe = 1;
	return 0;
}

static int mcdma_reset_queue(struct mcdma_queue *q)
{
	return mcdma_reg_write_verify(q, MCDMA_QCSR_Q_RESET, MCDMA_QCSR_Q_RESET_MASK,
				   1, MCDMA_QCSR_Q_RESET_SHIFT, MCDMA_Q_RESET_TO, 0);
}

/* Stop DMA before releasing mbufs still posted on the ring. */
static int mcdma_quiesce_queue(struct mcdma_queue *q)
{
	int ret;

	ret = mcdma_wait_queue_drain(q);
	if (ret != 0)
		return ret;

	mcdma_dev_descq_disable(q);

	ret = mcdma_reset_queue(q);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "queue %u reset failed (%d)", q->qid, ret);
		return ret;
	}

	return 0;
}

static int mcdma_dev_queue_init(struct mcdma_queue *q)
{
	struct rte_eth_dev *dev = q->ethdev;
	mcdma_qcsr_q_ctrl_t q_ctrl;
	uint32_t payload;
	uint64_t cons_idx;

	/* Empty queue: all HW didx counters at 0; first fill is didx 1. */
	q->cons_didx = 0;
	q->freed_cons_didx = 0;
	q->submitted_didx = 0;
	q->prod_didx = 0;
	q->didx = 0;
	q->burst_size = MCDMA_MAX_BURST;

	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_START_ADDR_L, q->qbuf_dma);
	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_START_ADDR_H, q->qbuf_dma >> 32);
	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_SIZE, (uint32_t)log2(q->num_descs));
	cons_idx = rte_mem_virt2iova((const void *)(uintptr_t)&q->cons_didx);
	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_CONSUMED_HEAD_ADDR_L, cons_idx);
	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_CONSUMED_HEAD_ADDR_H,
			      cons_idx >> 32);
	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_BATCH_DELAY,
			      MCDMA_BATCH_DESC_DELAY);

	if (q->dir == MCDMA_DIR_D2H) {
		if (q->rx_seg_len == 0) {
			PMD_DRV_LOG(ERR, "Rx queue %u: invalid segment length",
				    q->qid);
			return -EINVAL;
		}
		payload = RTE_ALIGN(q->rx_seg_len, RTE_CACHE_LINE_SIZE);
	} else {
		payload = RTE_ALIGN(mcdma_rx_frame_len_from_mtu(mcdma_dev_mtu_get(dev)),
				    RTE_CACHE_LINE_SIZE);
	}

	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_CPL_TIMEOUT, 0);
	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_PAYLOAD_COUNT, payload);

	q_ctrl.val = 0;
	q_ctrl.field.q_en = 1;
	if (q->wbe)
		q_ctrl.field.q_wb_en = 1;

	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_CTRL, q_ctrl.val);
	return 0;
}

static int mcdma_dev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
				    uint16_t nb_tx_desc,
				    unsigned int socket_id,
				    const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct mcdma_pci_device *mcdma_dev = dev->data->dev_private;
	struct mcdma_queue *txq = NULL;
	int ret;

	if (tx_queue_id >= mcdma_dev->ip_num_chan) {
		PMD_DRV_LOG(ERR, "TX queue id %u >= max channels %u",
			    tx_queue_id, mcdma_dev->ip_num_chan);
		return -EINVAL;
	}

	ret = mcdma_sw_descq_alloc(dev, &txq, MCDMA_DIR_H2D, tx_queue_id,
				   nb_tx_desc, socket_id);
	if (ret < 0)
		return ret;

	ret = mcdma_dev_descq_alloc(dev, txq);
	if (ret < 0) {
		mcdma_dev_descq_free(txq);
		rte_free(txq);
		return ret;
	}

	ret = mcdma_reset_queue(txq);
	if (ret) {
		mcdma_dev_descq_free(txq);
		rte_free(txq);
		return ret;
	}

	dev->data->tx_queues[tx_queue_id] = txq;
	return 0;
}

static int mcdma_dev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
				    uint16_t nb_rx_desc,
				    unsigned int socket_id,
				    const struct rte_eth_rxconf *rx_conf __rte_unused,
				    struct rte_mempool *mb_pool)
{
	struct mcdma_pci_device *mcdma_dev = dev->data->dev_private;
	struct mcdma_queue *rxq = NULL;
	int ret;

	if (mb_pool)
		PMD_DRV_LOG_DBG(ERR,
				"qid: %u, mbuf_avail_count = %u, mbuf_in_use_count = %u",
				rx_queue_id, rte_mempool_avail_count(mb_pool),
				rte_mempool_in_use_count(mb_pool));
	if (rx_queue_id >= mcdma_dev->ip_num_chan) {
		PMD_DRV_LOG(ERR, "RX queue id %u >= max channels %u",
			    rx_queue_id, mcdma_dev->ip_num_chan);
		return -EINVAL;
	}

	if (mb_pool == NULL) {
		PMD_DRV_LOG(ERR, "Rx queue %u: mbuf pool required", rx_queue_id);
		return -EINVAL;
	}

	ret = mcdma_sw_descq_alloc(dev, &rxq, MCDMA_DIR_D2H, rx_queue_id,
				   nb_rx_desc, socket_id);
	if (ret < 0)
		return ret;

	rxq->mb_pool = mb_pool;

	ret = mcdma_rx_seg_len_for_pool(dev, mb_pool, &rxq->rx_seg_len);
	if (ret != 0) {
		mcdma_dev_descq_free(rxq);
		rte_free(rxq);
		return ret;
	}

	ret = mcdma_dev_descq_alloc(dev, rxq);
	if (ret < 0) {
		mcdma_dev_descq_free(rxq);
		rte_free(rxq);
		return ret;
	}

	ret = mcdma_reset_queue(rxq);
	if (ret) {
		mcdma_dev_descq_free(rxq);
		rte_free(rxq);
		return ret;
	}

	dev->data->rx_queues[rx_queue_id] = rxq;
	return 0;
}

static int mcdma_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t qid)
{
	struct mcdma_queue *txq = dev->data->tx_queues[qid];
	int ret;

	if (txq == NULL)
		return -EINVAL;

	ret = mcdma_dev_queue_init(txq);
	if (ret)
		return ret;

	dev->data->tx_queue_state[qid] = RTE_ETH_QUEUE_STATE_STARTED;
	return 0;
}

static int mcdma_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t qid)
{
	struct mcdma_queue *rxq = dev->data->rx_queues[qid];
	int ret;

	if (rxq == NULL)
		return -EINVAL;

	ret = mcdma_dev_queue_init(rxq);
	if (ret)
		return ret;

	dev->data->rx_queue_state[qid] = RTE_ETH_QUEUE_STATE_STARTED;
	return 0;
}

static int mcdma_dev_start(struct rte_eth_dev *dev)
{
	uint16_t qid;
	int err;

	for (qid = 0; qid < dev->data->nb_tx_queues; qid++) {
		if (dev->data->tx_queues[qid] == NULL)
			continue;
		err = mcdma_dev_tx_queue_start(dev, qid);
		if (err != 0)
			goto stop_started;
	}

	for (qid = 0; qid < dev->data->nb_rx_queues; qid++) {
		if (dev->data->rx_queues[qid] == NULL)
			continue;
		err = mcdma_dev_rx_queue_start(dev, qid);
		if (err != 0)
			goto stop_started;
	}

	return 0;

stop_started:
	for (qid = 0; qid < dev->data->nb_rx_queues; qid++) {
		if (dev->data->rx_queues[qid] == NULL)
			continue;
		(void)mcdma_dev_rx_queue_stop(dev, qid);
	}
	for (qid = 0; qid < dev->data->nb_tx_queues; qid++) {
		if (dev->data->tx_queues[qid] == NULL)
			continue;
		(void)mcdma_dev_tx_queue_stop(dev, qid);
	}

	return err;
}

static int mcdma_dev_stop(struct rte_eth_dev *dev)
{
	uint16_t qid;
	int ret;
	int err = 0;

	for (qid = 0; qid < dev->data->nb_tx_queues; qid++) {
		ret = mcdma_dev_tx_queue_stop(dev, qid);
		if (ret != 0 && err == 0)
			err = ret;
	}
	for (qid = 0; qid < dev->data->nb_rx_queues; qid++) {
		ret = mcdma_dev_rx_queue_stop(dev, qid);
		if (ret != 0 && err == 0)
			err = ret;
	}

	return err;
}

static int mcdma_dev_link_update(struct rte_eth_dev *dev,
				 __rte_unused int wait_to_complete)
{
	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;
	dev->data->dev_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;

	return 0;
}

static void
mcdma_dev_queue_release_common(struct rte_eth_dev *dev, struct mcdma_queue *q,
			       uint16_t qid, bool is_rx)
{
	if (q == NULL)
		return;

	if (is_rx) {
		if (dev->data->rx_queue_state[qid] == RTE_ETH_QUEUE_STATE_STARTED) {
			if (mcdma_quiesce_queue(q) != 0)
				PMD_DRV_LOG(WARNING,
					    "Rx queue %u quiesce failed on release",
					    qid);
			mcdma_sw_ring_free_inflight(q);
			dev->data->rx_queue_state[qid] =
				RTE_ETH_QUEUE_STATE_STOPPED;
		}
		dev->data->rx_queues[qid] = NULL;
	} else {
		if (dev->data->tx_queue_state[qid] == RTE_ETH_QUEUE_STATE_STARTED) {
			if (mcdma_quiesce_queue(q) != 0)
				PMD_DRV_LOG(WARNING,
					    "Tx queue %u quiesce failed on release",
					    qid);
			mcdma_sw_ring_free_inflight(q);
			dev->data->tx_queue_state[qid] =
				RTE_ETH_QUEUE_STATE_STOPPED;
		}
		dev->data->tx_queues[qid] = NULL;
	}

	mcdma_dev_descq_disable(q);
	mcdma_dev_descq_free(q);
	rte_free(q);
}

static void mcdma_dev_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	mcdma_dev_queue_release_common(dev, dev->data->tx_queues[qid], qid,
				       false);
}

static void mcdma_dev_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	mcdma_dev_queue_release_common(dev, dev->data->rx_queues[qid], qid,
				       true);
}

static int mcdma_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t qid)
{
	struct mcdma_queue *q;
	int ret;

	if (!dev->data->tx_queue_state[qid])
		return 0;

	q = dev->data->tx_queues[qid];
	if (q == NULL)
		return 0;

	ret = mcdma_quiesce_queue(q);
	if (ret != 0)
		return ret;

	mcdma_sw_ring_free_inflight(q);

	dev->data->tx_queue_state[qid] = RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}

static int mcdma_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t qid)
{
	struct mcdma_queue *q;
	int ret;

	if (!dev->data->rx_queue_state[qid])
		return 0;

	q = dev->data->rx_queues[qid];
	if (q == NULL)
		return 0;

	ret = mcdma_quiesce_queue(q);
	if (ret != 0)
		return ret;

	mcdma_sw_ring_free_inflight(q);

	dev->data->rx_queue_state[qid] = RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}

static int mcdma_dev_infos_get(struct rte_eth_dev *dev,
			       struct rte_eth_dev_info *dev_info)
{
	struct mcdma_pci_device *mcdma_dev = dev->data->dev_private;

	dev_info->max_rx_queues = mcdma_dev->ip_num_chan;
	dev_info->max_tx_queues = mcdma_dev->ip_num_chan;
	dev_info->max_rx_pktlen = MCDMA_MAX_RX_FRAME_LEN;
	dev_info->max_mac_addrs = MCDMA_MAX_MAC_ADDRS;
	dev_info->default_rxportconf.burst_size = MCDMA_MAX_BURST;
	dev_info->dev_capa =
		RTE_ETH_DEV_CAPA_RUNTIME_RX_QUEUE_SETUP |
		RTE_ETH_DEV_CAPA_RUNTIME_TX_QUEUE_SETUP;
	dev_info->dev_capa &= ~RTE_ETH_DEV_CAPA_FLOW_RULE_KEEP;
	/* Multi-seg Tx: one sw_ring owner (head on EOF desc); see H2D prepare. */
	dev_info->tx_offload_capa = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
	dev_info->min_mtu = MCDMA_MIN_MTU;
	dev_info->max_mtu = MCDMA_MAX_MTU;
	dev_info->rx_desc_lim.nb_max = MCDMA_MAX_RING_DESCS;
	dev_info->rx_desc_lim.nb_min = MCDMA_NUM_DESC_PER_PAGE;
	dev_info->rx_desc_lim.nb_align = MCDMA_NUM_DESC_PER_PAGE;
	dev_info->tx_desc_lim.nb_max = MCDMA_MAX_RING_DESCS;
	dev_info->tx_desc_lim.nb_min = MCDMA_NUM_DESC_PER_PAGE;
	dev_info->tx_desc_lim.nb_align = MCDMA_NUM_DESC_PER_PAGE;

	return 0;
}

static int mcdma_dev_configure(struct rte_eth_dev *dev)
{
	struct mcdma_pci_device *mcdma_dev = dev->data->dev_private;
	int ret;

	if (RTE_MAX(dev->data->nb_rx_queues, dev->data->nb_tx_queues) >
	    (uint16_t)mcdma_dev->ip_num_chan) {
		PMD_DRV_LOG(ERR, "Max number of channels supported %u",
			    mcdma_dev->ip_num_chan);
		return -EINVAL;
	}

	ret = mcdma_rx_frame_len_check(dev,
			mcdma_rx_frame_len_from_mtu(mcdma_dev_mtu_get(dev)));
	if (ret != 0)
		return ret;

	if (dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_SCATTER) {
		PMD_DRV_LOG(ERR, "Rx scattered/multi-segment mbufs not supported");
		return -EINVAL;
	}

	dev->data->scattered_rx = 0;

	/* perform IP Reset - only from PF0 */
	if (mcdma_dev->is_pf && !mcdma_dev->pf_idx) {
		mcdma_dmacsr_reg_writel(mcdma_dev->bar_base,
					MCDMA_CSR_SW_RESET, 0x1);
		rte_delay_ms(MCDMA_SW_RESET_DELAY_MS);
	}

	return 0;
}

static int mcdma_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	uint32_t frame_len;
	uint16_t qid;
	int ret;

	if (mtu < MCDMA_MIN_MTU || mtu > MCDMA_MAX_MTU)
		return -EINVAL;

	frame_len = mcdma_rx_frame_len_from_mtu(mtu);
	ret = mcdma_rx_frame_len_check(dev, frame_len);
	if (ret != 0)
		return ret;

	for (qid = 0; qid < dev->data->nb_rx_queues; qid++) {
		struct mcdma_queue *rxq = dev->data->rx_queues[qid];
		uint32_t buf_len;

		if (rxq == NULL || rxq->mb_pool == NULL)
			continue;

		buf_len = rte_pktmbuf_data_room_size(rxq->mb_pool);
		if (buf_len <= RTE_PKTMBUF_HEADROOM) {
			PMD_DRV_LOG(ERR, "port %u: mbuf pool data room %u too small",
				    dev->data->port_id, buf_len);
			return -EINVAL;
		}
		buf_len -= RTE_PKTMBUF_HEADROOM;
		if (frame_len > buf_len) {
			PMD_DRV_LOG(ERR,
				    "port %u: Rx frame %u B exceeds mbuf data room %u B (MTU %u)",
				    dev->data->port_id, frame_len, buf_len, mtu);
			return -EINVAL;
		}

		rxq->rx_seg_len = frame_len;
	}

	dev->data->dev_conf.rxmode.mtu = mtu;
	dev->data->mtu = mtu;

	return 0;
}

static uint64_t
mcdma_qcsr_read_drop_count(struct mcdma_queue *q)
{
	uint32_t reg;

	reg = mcdma_qcsr_reg_readl(q->qcsr, MCDMA_QCSR_Q_DATA_DRP_ERR_CTR);
	if (reg & MCDMA_QCSR_DRP_CTR_VALID) {
		q->drop_pkts += reg & MCDMA_QCSR_DRP_CTR_CNT_MASK;
		reg &= ~MCDMA_QCSR_DRP_CTR_CLR_MASK;
		mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_DATA_DRP_ERR_CTR, reg);
	}

	return q->drop_pkts;
}

static uint64_t
mcdma_qcsr_read_ptr_errors(struct mcdma_queue *q)
{
	uint32_t reg;
	uint64_t errs = 0;

	reg = mcdma_qcsr_reg_readl(q->qcsr, MCDMA_QCSR_Q_HEAD_POINTER);
	if (reg & MCDMA_QCSR_PTR_ERR_MASK)
		errs++;

	reg = mcdma_qcsr_reg_readl(q->qcsr, MCDMA_QCSR_Q_COMPLETED_POINTER);
	if (reg & MCDMA_QCSR_PTR_ERR_MASK)
		errs++;

	return errs;
}

int mcdma_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats,
			struct eth_queue_stats *qstats)
{
	struct mcdma_queue *q;
	uint16_t i;
	uint64_t drops;
	uint64_t q_errs;

	if (stats == NULL)
		return -EINVAL;

	memset(stats, 0, sizeof(*stats));

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		q = dev->data->rx_queues[i];
		if (q == NULL)
			continue;

		drops = mcdma_qcsr_read_drop_count(q);
		q_errs = mcdma_qcsr_read_ptr_errors(q);
		stats->ipackets += q->rx_pkts;
		stats->ibytes += q->rx_bytes;
		stats->imissed += drops;
		stats->ierrors += q_errs;
		stats->rx_nombuf += q->rx_nombuf;

		if (qstats != NULL) {
			qstats[i].q_ipackets = q->rx_pkts;
			qstats[i].q_ibytes = q->rx_bytes;
		}
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		q = dev->data->tx_queues[i];
		if (q == NULL)
			continue;

		(void)mcdma_qcsr_read_drop_count(q);
		q_errs = mcdma_qcsr_read_ptr_errors(q);
		stats->opackets += q->tx_pkts;
		stats->obytes += q->tx_bytes;
		stats->oerrors += q_errs;

		if (qstats != NULL) {
			qstats[i].q_opackets = q->tx_pkts;
			qstats[i].q_obytes = q->tx_bytes;
		}
	}

	return 0;
}

static unsigned int
mcdma_xstats_count(const struct rte_eth_dev *dev)
{
	return dev->data->nb_rx_queues + dev->data->nb_tx_queues;
}

static int
mcdma_dev_xstats_get_names(struct rte_eth_dev *dev,
			   struct rte_eth_xstat_name *xstats_names,
			   unsigned int n)
{
	unsigned int i;
	unsigned int count = 0;
	unsigned int nstats = mcdma_xstats_count(dev);

	if (xstats_names == NULL || n < nstats)
		return nstats;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		snprintf(xstats_names[count].name,
			 sizeof(xstats_names[count].name),
			 "rx_q%u_errors", i);
		count++;
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		snprintf(xstats_names[count].name,
			 sizeof(xstats_names[count].name),
			 "tx_q%u_errors", i);
		count++;
	}

	return count;
}

static int
mcdma_dev_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *xstats,
		     unsigned int n)
{
	unsigned int i;
	unsigned int count = 0;
	unsigned int nstats = mcdma_xstats_count(dev);

	if (xstats == NULL || n < nstats)
		return nstats;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct mcdma_queue *q = dev->data->rx_queues[i];
		uint64_t errors = 0;

		if (q != NULL)
			errors = mcdma_qcsr_read_drop_count(q) +
				 mcdma_qcsr_read_ptr_errors(q);

		xstats[count].id = count;
		xstats[count].value = errors;
		count++;
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct mcdma_queue *q = dev->data->tx_queues[i];
		uint64_t errors = 0;

		if (q != NULL)
			errors = mcdma_qcsr_read_ptr_errors(q);

		xstats[count].id = count;
		xstats[count].value = errors;
		count++;
	}

	return count;
}

static struct eth_dev_ops mcdma_ethdev_ops = {
	.dev_configure        = mcdma_dev_configure,
	.dev_infos_get        = mcdma_dev_infos_get,
	.dev_start            = mcdma_dev_start,
	.dev_stop             = mcdma_dev_stop,
	.link_update          = mcdma_dev_link_update,
	.rx_queue_setup       = mcdma_dev_rx_queue_setup,
	.tx_queue_setup       = mcdma_dev_tx_queue_setup,
	.rx_queue_release     = mcdma_dev_rx_queue_release,
	.tx_queue_release     = mcdma_dev_tx_queue_release,
	.rx_queue_start       = mcdma_dev_rx_queue_start,
	.rx_queue_stop        = mcdma_dev_rx_queue_stop,
	.tx_queue_start       = mcdma_dev_tx_queue_start,
	.tx_queue_stop        = mcdma_dev_tx_queue_stop,
	.stats_get            = mcdma_dev_stats_get,
	.xstats_get           = mcdma_dev_xstats_get,
	.xstats_get_names     = mcdma_dev_xstats_get_names,
	.mtu_set              = mcdma_dev_mtu_set,
};

void mcdma_ethdev_ops_init(struct rte_eth_dev *dev)
{
	dev->dev_ops = &mcdma_ethdev_ops;
	dev->rx_pkt_burst = &mcdma_recv_pkts;
	dev->tx_pkt_burst = &mcdma_xmit_pkts;
}
