/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2022 Advanced Micro Devices, Inc.
 */

#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <rte_prefetch.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>
#include <rte_string_fns.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_net.h>

#include "ionic_logs.h"
#include "ionic_mac_api.h"
#include "ionic_ethdev.h"
#include "ionic_lif.h"
#include "ionic_rxtx.h"

static void
ionic_empty_array(void **array, uint32_t cnt, uint16_t idx)
{
	uint32_t i;

	for (i = idx; i < cnt; i++)
		if (array[i])
			rte_pktmbuf_free_seg(array[i]);

	memset(array, 0, sizeof(void *) * cnt);
}

static void __rte_cold
ionic_tx_empty(struct ionic_tx_qcq *txq)
{
	struct ionic_queue *q = &txq->qcq.q;

	ionic_empty_array(q->info, q->num_descs * q->num_segs, 0);
}

static void __rte_cold
ionic_rx_empty(struct ionic_rx_qcq *rxq)
{
	struct ionic_queue *q = &rxq->qcq.q;

	/*
	 * Walk the full info array so that the clean up includes any
	 * fragments that were left dangling for later reuse
	 */
	ionic_empty_array(q->info, q->num_descs * q->num_segs, 0);
}

/*********************************************************************
 *
 *  TX functions
 *
 **********************************************************************/

void
ionic_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
		struct rte_eth_txq_info *qinfo)
{
	struct ionic_tx_qcq *txq = dev->data->tx_queues[queue_id];
	struct ionic_queue *q = &txq->qcq.q;

	qinfo->nb_desc = q->num_descs;
	qinfo->conf.offloads = dev->data->dev_conf.txmode.offloads;
	qinfo->conf.tx_deferred_start = txq->flags & IONIC_QCQ_F_DEFERRED;
}

static __rte_always_inline void
ionic_tx_flush(struct ionic_tx_qcq *txq)
{
	struct ionic_cq *cq = &txq->qcq.cq;
	struct ionic_queue *q = &txq->qcq.q;
	struct rte_mbuf *txm;
	struct ionic_txq_comp *cq_desc, *cq_desc_base = cq->base;
	void **info;
	uint32_t i;

	cq_desc = &cq_desc_base[cq->tail_idx];

	while (color_match(cq_desc->color, cq->done_color)) {
		cq->tail_idx = Q_NEXT_TO_SRVC(cq, 1);
		if (cq->tail_idx == 0)
			cq->done_color = !cq->done_color;

		/* Prefetch 4 x 16B comp at cq->tail_idx + 4 */
		if ((cq->tail_idx & 0x3) == 0)
			rte_prefetch0(&cq_desc_base[Q_NEXT_TO_SRVC(cq, 4)]);

		while (q->tail_idx != rte_le_to_cpu_16(cq_desc->comp_index)) {
			/* Prefetch 8 mbuf ptrs at q->tail_idx + 2 */
			rte_prefetch0(IONIC_INFO_PTR(q, Q_NEXT_TO_SRVC(q, 2)));

			/* Prefetch next mbuf */
			void **next_info =
				IONIC_INFO_PTR(q, Q_NEXT_TO_SRVC(q, 1));
			if (next_info[0])
				rte_mbuf_prefetch_part2(next_info[0]);
			if (next_info[1])
				rte_mbuf_prefetch_part2(next_info[1]);

			info = IONIC_INFO_PTR(q, q->tail_idx);
			for (i = 0; i < q->num_segs; i++) {
				txm = info[i];
				if (!txm)
					break;

				rte_pktmbuf_free_seg(txm);

				info[i] = NULL;
			}

			q->tail_idx = Q_NEXT_TO_SRVC(q, 1);
		}

		cq_desc = &cq_desc_base[cq->tail_idx];
	}
}

void __rte_cold
ionic_dev_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	struct ionic_tx_qcq *txq = dev->data->tx_queues[qid];

	IONIC_PRINT_CALL();

	ionic_qcq_free(&txq->qcq);
}

int __rte_cold
ionic_dev_tx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t tx_queue_id)
{
	struct ionic_tx_stats *stats;
	struct ionic_tx_qcq *txq;

	IONIC_PRINT(DEBUG, "Stopping TX queue %u", tx_queue_id);

	txq = eth_dev->data->tx_queues[tx_queue_id];

	eth_dev->data->tx_queue_state[tx_queue_id] =
		RTE_ETH_QUEUE_STATE_STOPPED;

	/*
	 * Note: we should better post NOP Tx desc and wait for its completion
	 * before disabling Tx queue
	 */

	ionic_lif_txq_deinit(txq);

	/* Free all buffers from descriptor ring */
	ionic_tx_empty(txq);

	stats = &txq->stats;
	IONIC_PRINT(DEBUG, "TX queue %u pkts %ju tso %ju",
		txq->qcq.q.index, stats->packets, stats->tso);

	return 0;
}

int __rte_cold
ionic_dev_tx_queue_setup(struct rte_eth_dev *eth_dev, uint16_t tx_queue_id,
		uint16_t nb_desc, uint32_t socket_id,
		const struct rte_eth_txconf *tx_conf)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_tx_qcq *txq;
	uint64_t offloads;
	int err;

	if (tx_queue_id >= lif->ntxqcqs) {
		IONIC_PRINT(DEBUG, "Queue index %u not available "
			"(max %u queues)",
			tx_queue_id, lif->ntxqcqs);
		return -EINVAL;
	}

	offloads = tx_conf->offloads | eth_dev->data->dev_conf.txmode.offloads;
	IONIC_PRINT(DEBUG,
		"Configuring skt %u TX queue %u with %u buffers, offloads %jx",
		socket_id, tx_queue_id, nb_desc, offloads);

	/* Validate number of receive descriptors */
	if (!rte_is_power_of_2(nb_desc) || nb_desc < IONIC_MIN_RING_DESC)
		return -EINVAL; /* or use IONIC_DEFAULT_RING_DESC */

	/* Free memory prior to re-allocation if needed... */
	if (eth_dev->data->tx_queues[tx_queue_id] != NULL) {
		ionic_dev_tx_queue_release(eth_dev, tx_queue_id);
		eth_dev->data->tx_queues[tx_queue_id] = NULL;
	}

	eth_dev->data->tx_queue_state[tx_queue_id] =
		RTE_ETH_QUEUE_STATE_STOPPED;

	err = ionic_tx_qcq_alloc(lif, socket_id, tx_queue_id, nb_desc, &txq);
	if (err) {
		IONIC_PRINT(DEBUG, "Queue allocation failure");
		return -EINVAL;
	}

	/* Do not start queue with rte_eth_dev_start() */
	if (tx_conf->tx_deferred_start)
		txq->flags |= IONIC_QCQ_F_DEFERRED;

	/* Convert the offload flags into queue flags */
	if (offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
		txq->flags |= IONIC_QCQ_F_CSUM_L3;
	if (offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
		txq->flags |= IONIC_QCQ_F_CSUM_TCP;
	if (offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
		txq->flags |= IONIC_QCQ_F_CSUM_UDP;

	eth_dev->data->tx_queues[tx_queue_id] = txq;

	return 0;
}

/*
 * Start Transmit Units for specified queue.
 */
int __rte_cold
ionic_dev_tx_queue_start(struct rte_eth_dev *eth_dev, uint16_t tx_queue_id)
{
	uint8_t *tx_queue_state = eth_dev->data->tx_queue_state;
	struct ionic_tx_qcq *txq;
	int err;

	if (tx_queue_state[tx_queue_id] == RTE_ETH_QUEUE_STATE_STARTED) {
		IONIC_PRINT(DEBUG, "TX queue %u already started",
			tx_queue_id);
		return 0;
	}

	txq = eth_dev->data->tx_queues[tx_queue_id];

	IONIC_PRINT(DEBUG, "Starting TX queue %u, %u descs",
		tx_queue_id, txq->qcq.q.num_descs);

	err = ionic_lif_txq_init(txq);
	if (err)
		return err;

	tx_queue_state[tx_queue_id] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

static void
ionic_tx_tcp_pseudo_csum(struct rte_mbuf *txm)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(txm, struct ether_hdr *);
	char *l3_hdr = ((char *)eth_hdr) + txm->l2_len;
	struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)
		(l3_hdr + txm->l3_len);

	if (txm->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
		struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;
		ipv4_hdr->hdr_checksum = 0;
		tcp_hdr->cksum = 0;
		tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
	} else {
		struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)l3_hdr;
		tcp_hdr->cksum = 0;
		tcp_hdr->cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, tcp_hdr);
	}
}

static void
ionic_tx_tcp_inner_pseudo_csum(struct rte_mbuf *txm)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(txm, struct ether_hdr *);
	char *l3_hdr = ((char *)eth_hdr) + txm->outer_l2_len +
		txm->outer_l3_len + txm->l2_len;
	struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)
		(l3_hdr + txm->l3_len);

	if (txm->ol_flags & RTE_MBUF_F_TX_IPV4) {
		struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;
		ipv4_hdr->hdr_checksum = 0;
		tcp_hdr->cksum = 0;
		tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
	} else {
		struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)l3_hdr;
		tcp_hdr->cksum = 0;
		tcp_hdr->cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, tcp_hdr);
	}
}

static void
ionic_tx_tso_post(struct ionic_queue *q, struct ionic_txq_desc *desc,
		struct rte_mbuf *txm,
		rte_iova_t addr, uint8_t nsge, uint16_t len,
		uint32_t hdrlen, uint32_t mss,
		bool encap,
		uint16_t vlan_tci, bool has_vlan,
		bool start, bool done)
{
	struct rte_mbuf *txm_seg;
	void **info;
	uint64_t cmd;
	uint8_t flags = 0;
	int i;

	flags |= has_vlan ? IONIC_TXQ_DESC_FLAG_VLAN : 0;
	flags |= encap ? IONIC_TXQ_DESC_FLAG_ENCAP : 0;
	flags |= start ? IONIC_TXQ_DESC_FLAG_TSO_SOT : 0;
	flags |= done ? IONIC_TXQ_DESC_FLAG_TSO_EOT : 0;

	cmd = encode_txq_desc_cmd(IONIC_TXQ_DESC_OPCODE_TSO,
		flags, nsge, addr);
	desc->cmd = rte_cpu_to_le_64(cmd);
	desc->len = rte_cpu_to_le_16(len);
	desc->vlan_tci = rte_cpu_to_le_16(vlan_tci);
	desc->hdr_len = rte_cpu_to_le_16(hdrlen);
	desc->mss = rte_cpu_to_le_16(mss);

	if (done) {
		info = IONIC_INFO_PTR(q, q->head_idx);

		/* Walk the mbuf chain to stash pointers in the array */
		txm_seg = txm;
		for (i = 0; i < txm->nb_segs; i++) {
			info[i] = txm_seg;
			txm_seg = txm_seg->next;
		}
	}

	q->head_idx = Q_NEXT_TO_POST(q, 1);
}

static struct ionic_txq_desc *
ionic_tx_tso_next(struct ionic_tx_qcq *txq, struct ionic_txq_sg_elem **elem)
{
	struct ionic_queue *q = &txq->qcq.q;
	struct ionic_txq_desc *desc_base = q->base;
	struct ionic_txq_sg_desc_v1 *sg_desc_base = q->sg_base;
	struct ionic_txq_desc *desc = &desc_base[q->head_idx];
	struct ionic_txq_sg_desc_v1 *sg_desc = &sg_desc_base[q->head_idx];

	*elem = sg_desc->elems;
	return desc;
}

static int
ionic_tx_tso(struct ionic_tx_qcq *txq, struct rte_mbuf *txm)
{
	struct ionic_queue *q = &txq->qcq.q;
	struct ionic_tx_stats *stats = &txq->stats;
	struct ionic_txq_desc *desc;
	struct ionic_txq_sg_elem *elem;
	struct rte_mbuf *txm_seg;
	rte_iova_t data_iova;
	uint64_t desc_addr = 0, next_addr;
	uint16_t desc_len = 0;
	uint8_t desc_nsge;
	uint32_t hdrlen;
	uint32_t mss = txm->tso_segsz;
	uint32_t frag_left = 0;
	uint32_t left;
	uint32_t seglen;
	uint32_t len;
	uint32_t offset = 0;
	bool start, done;
	bool encap;
	bool has_vlan = !!(txm->ol_flags & RTE_MBUF_F_TX_VLAN);
	uint16_t vlan_tci = txm->vlan_tci;
	uint64_t ol_flags = txm->ol_flags;

	encap = ((ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM) ||
		 (ol_flags & RTE_MBUF_F_TX_OUTER_UDP_CKSUM)) &&
		((ol_flags & RTE_MBUF_F_TX_OUTER_IPV4) ||
		 (ol_flags & RTE_MBUF_F_TX_OUTER_IPV6));

	/* Preload inner-most TCP csum field with IP pseudo hdr
	 * calculated with IP length set to zero.  HW will later
	 * add in length to each TCP segment resulting from the TSO.
	 */

	if (encap) {
		ionic_tx_tcp_inner_pseudo_csum(txm);
		hdrlen = txm->outer_l2_len + txm->outer_l3_len +
			txm->l2_len + txm->l3_len + txm->l4_len;
	} else {
		ionic_tx_tcp_pseudo_csum(txm);
		hdrlen = txm->l2_len + txm->l3_len + txm->l4_len;
	}

	seglen = hdrlen + mss;
	left = txm->data_len;
	data_iova = rte_mbuf_data_iova(txm);

	desc = ionic_tx_tso_next(txq, &elem);
	start = true;

	/* Chop data up into desc segments */

	while (left > 0) {
		len = RTE_MIN(seglen, left);
		frag_left = seglen - len;
		desc_addr = rte_cpu_to_le_64(data_iova + offset);
		desc_len = len;
		desc_nsge = 0;
		left -= len;
		offset += len;
		if (txm->nb_segs > 1 && frag_left > 0)
			continue;
		done = (txm->nb_segs == 1 && left == 0);
		ionic_tx_tso_post(q, desc, txm,
			desc_addr, desc_nsge, desc_len,
			hdrlen, mss,
			encap,
			vlan_tci, has_vlan,
			start, done);
		desc = ionic_tx_tso_next(txq, &elem);
		start = false;
		seglen = mss;
	}

	/* Chop frags into desc segments */

	txm_seg = txm->next;
	while (txm_seg != NULL) {
		offset = 0;
		data_iova = rte_mbuf_data_iova(txm_seg);
		left = txm_seg->data_len;

		while (left > 0) {
			next_addr = rte_cpu_to_le_64(data_iova + offset);
			if (frag_left > 0) {
				len = RTE_MIN(frag_left, left);
				frag_left -= len;
				elem->addr = next_addr;
				elem->len = rte_cpu_to_le_16(len);
				elem++;
				desc_nsge++;
			} else {
				len = RTE_MIN(mss, left);
				frag_left = mss - len;
				desc_addr = next_addr;
				desc_len = len;
				desc_nsge = 0;
			}
			left -= len;
			offset += len;
			if (txm_seg->next != NULL && frag_left > 0)
				continue;

			done = (txm_seg->next == NULL && left == 0);
			ionic_tx_tso_post(q, desc, txm_seg,
				desc_addr, desc_nsge, desc_len,
				hdrlen, mss,
				encap,
				vlan_tci, has_vlan,
				start, done);
			desc = ionic_tx_tso_next(txq, &elem);
			start = false;
		}

		txm_seg = txm_seg->next;
	}

	stats->tso++;

	return 0;
}

static __rte_always_inline int
ionic_tx(struct ionic_tx_qcq *txq, struct rte_mbuf *txm)
{
	struct ionic_queue *q = &txq->qcq.q;
	struct ionic_txq_desc *desc, *desc_base = q->base;
	struct ionic_txq_sg_desc_v1 *sg_desc_base = q->sg_base;
	struct ionic_txq_sg_elem *elem;
	struct ionic_tx_stats *stats = &txq->stats;
	struct rte_mbuf *txm_seg;
	void **info;
	rte_iova_t data_iova;
	uint64_t ol_flags = txm->ol_flags;
	uint64_t addr, cmd;
	uint8_t opcode = IONIC_TXQ_DESC_OPCODE_CSUM_NONE;
	uint8_t flags = 0;

	desc = &desc_base[q->head_idx];
	info = IONIC_INFO_PTR(q, q->head_idx);

	if ((ol_flags & RTE_MBUF_F_TX_IP_CKSUM) &&
	    (txq->flags & IONIC_QCQ_F_CSUM_L3)) {
		opcode = IONIC_TXQ_DESC_OPCODE_CSUM_HW;
		flags |= IONIC_TXQ_DESC_FLAG_CSUM_L3;
	}

	if (((ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) &&
	     (txq->flags & IONIC_QCQ_F_CSUM_TCP)) ||
	    ((ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) &&
	     (txq->flags & IONIC_QCQ_F_CSUM_UDP))) {
		opcode = IONIC_TXQ_DESC_OPCODE_CSUM_HW;
		flags |= IONIC_TXQ_DESC_FLAG_CSUM_L4;
	}

	if (opcode == IONIC_TXQ_DESC_OPCODE_CSUM_NONE)
		stats->no_csum++;

	if (((ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM) ||
	     (ol_flags & RTE_MBUF_F_TX_OUTER_UDP_CKSUM)) &&
	    ((ol_flags & RTE_MBUF_F_TX_OUTER_IPV4) ||
	     (ol_flags & RTE_MBUF_F_TX_OUTER_IPV6))) {
		flags |= IONIC_TXQ_DESC_FLAG_ENCAP;
	}

	if (ol_flags & RTE_MBUF_F_TX_VLAN) {
		flags |= IONIC_TXQ_DESC_FLAG_VLAN;
		desc->vlan_tci = rte_cpu_to_le_16(txm->vlan_tci);
	}

	addr = rte_cpu_to_le_64(rte_mbuf_data_iova(txm));

	cmd = encode_txq_desc_cmd(opcode, flags, txm->nb_segs - 1, addr);
	desc->cmd = rte_cpu_to_le_64(cmd);
	desc->len = rte_cpu_to_le_16(txm->data_len);

	info[0] = txm;

	if (txm->nb_segs > 1) {
		txm_seg = txm->next;

		elem = sg_desc_base[q->head_idx].elems;

		while (txm_seg != NULL) {
			/* Stash the mbuf ptr in the array */
			info++;
			*info = txm_seg;

			/* Configure the SGE */
			data_iova = rte_mbuf_data_iova(txm_seg);
			elem->len = rte_cpu_to_le_16(txm_seg->data_len);
			elem->addr = rte_cpu_to_le_64(data_iova);
			elem++;

			txm_seg = txm_seg->next;
		}
	}

	q->head_idx = Q_NEXT_TO_POST(q, 1);

	return 0;
}

uint16_t
ionic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts)
{
	struct ionic_tx_qcq *txq = tx_queue;
	struct ionic_queue *q = &txq->qcq.q;
	struct ionic_tx_stats *stats = &txq->stats;
	struct rte_mbuf *mbuf;
	uint32_t bytes_tx = 0;
	uint16_t nb_avail, nb_tx = 0;
	int err;

	struct ionic_txq_desc *desc_base = q->base;
	rte_prefetch0(&desc_base[q->head_idx]);
	rte_prefetch0(IONIC_INFO_PTR(q, q->head_idx));

	if (tx_pkts) {
		rte_mbuf_prefetch_part1(tx_pkts[0]);
		rte_mbuf_prefetch_part2(tx_pkts[0]);
	}

	/* Cleaning old buffers */
	ionic_tx_flush(txq);

	nb_avail = ionic_q_space_avail(q);
	if (unlikely(nb_avail < nb_pkts)) {
		stats->stop += nb_pkts - nb_avail;
		nb_pkts = nb_avail;
	}

	while (nb_tx < nb_pkts) {
		uint16_t next_idx = Q_NEXT_TO_POST(q, 1);
		rte_prefetch0(&desc_base[next_idx]);
		rte_prefetch0(IONIC_INFO_PTR(q, next_idx));

		if (nb_tx + 1 < nb_pkts) {
			rte_mbuf_prefetch_part1(tx_pkts[nb_tx + 1]);
			rte_mbuf_prefetch_part2(tx_pkts[nb_tx + 1]);
		}

		mbuf = tx_pkts[nb_tx];

		if (mbuf->ol_flags & RTE_MBUF_F_TX_TCP_SEG)
			err = ionic_tx_tso(txq, mbuf);
		else
			err = ionic_tx(txq, mbuf);
		if (err) {
			stats->drop += nb_pkts - nb_tx;
			break;
		}

		bytes_tx += mbuf->pkt_len;
		nb_tx++;
	}

	if (nb_tx > 0) {
		rte_wmb();
		ionic_q_flush(q);

		stats->packets += nb_tx;
		stats->bytes += bytes_tx;
	}

	return nb_tx;
}

/*********************************************************************
 *
 *  TX prep functions
 *
 **********************************************************************/

#define IONIC_TX_OFFLOAD_MASK (RTE_MBUF_F_TX_IPV4 |		\
	RTE_MBUF_F_TX_IPV6 |		\
	RTE_MBUF_F_TX_VLAN |		\
	RTE_MBUF_F_TX_IP_CKSUM |	\
	RTE_MBUF_F_TX_TCP_SEG |	\
	RTE_MBUF_F_TX_L4_MASK)

#define IONIC_TX_OFFLOAD_NOTSUP_MASK \
	(RTE_MBUF_F_TX_OFFLOAD_MASK ^ IONIC_TX_OFFLOAD_MASK)

uint16_t
ionic_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct ionic_tx_qcq *txq = tx_queue;
	struct rte_mbuf *txm;
	uint64_t offloads;
	int i = 0;

	for (i = 0; i < nb_pkts; i++) {
		txm = tx_pkts[i];

		if (txm->nb_segs > txq->num_segs_fw) {
			rte_errno = -EINVAL;
			break;
		}

		offloads = txm->ol_flags;

		if (offloads & IONIC_TX_OFFLOAD_NOTSUP_MASK) {
			rte_errno = -ENOTSUP;
			break;
		}
	}

	return i;
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/

void
ionic_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
		struct rte_eth_rxq_info *qinfo)
{
	struct ionic_rx_qcq *rxq = dev->data->rx_queues[queue_id];
	struct ionic_queue *q = &rxq->qcq.q;

	qinfo->mp = rxq->mb_pool;
	qinfo->scattered_rx = dev->data->scattered_rx;
	qinfo->nb_desc = q->num_descs;
	qinfo->conf.rx_deferred_start = rxq->flags & IONIC_QCQ_F_DEFERRED;
	qinfo->conf.offloads = dev->data->dev_conf.rxmode.offloads;
}

void __rte_cold
ionic_dev_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	struct ionic_rx_qcq *rxq = dev->data->rx_queues[qid];

	if (!rxq)
		return;

	IONIC_PRINT_CALL();

	ionic_qcq_free(&rxq->qcq);
}

int __rte_cold
ionic_dev_rx_queue_setup(struct rte_eth_dev *eth_dev,
		uint16_t rx_queue_id,
		uint16_t nb_desc,
		uint32_t socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mp)
{
	struct ionic_lif *lif = IONIC_ETH_DEV_TO_LIF(eth_dev);
	struct ionic_rx_qcq *rxq;
	uint64_t offloads;
	int err;

	if (rx_queue_id >= lif->nrxqcqs) {
		IONIC_PRINT(ERR,
			"Queue index %u not available (max %u queues)",
			rx_queue_id, lif->nrxqcqs);
		return -EINVAL;
	}

	offloads = rx_conf->offloads | eth_dev->data->dev_conf.rxmode.offloads;
	IONIC_PRINT(DEBUG,
		"Configuring skt %u RX queue %u with %u buffers, offloads %jx",
		socket_id, rx_queue_id, nb_desc, offloads);

	if (!rx_conf->rx_drop_en)
		IONIC_PRINT(WARNING, "No-drop mode is not supported");

	/* Validate number of receive descriptors */
	if (!rte_is_power_of_2(nb_desc) ||
			nb_desc < IONIC_MIN_RING_DESC ||
			nb_desc > IONIC_MAX_RING_DESC) {
		IONIC_PRINT(ERR,
			"Bad descriptor count (%u) for queue %u (min: %u)",
			nb_desc, rx_queue_id, IONIC_MIN_RING_DESC);
		return -EINVAL; /* or use IONIC_DEFAULT_RING_DESC */
	}

	/* Free memory prior to re-allocation if needed... */
	if (eth_dev->data->rx_queues[rx_queue_id] != NULL) {
		ionic_dev_rx_queue_release(eth_dev, rx_queue_id);
		eth_dev->data->rx_queues[rx_queue_id] = NULL;
	}

	eth_dev->data->rx_queue_state[rx_queue_id] =
		RTE_ETH_QUEUE_STATE_STOPPED;

	err = ionic_rx_qcq_alloc(lif, socket_id, rx_queue_id, nb_desc, mp,
			&rxq);
	if (err) {
		IONIC_PRINT(ERR, "Queue %d allocation failure", rx_queue_id);
		return -EINVAL;
	}

	rxq->mb_pool = mp;

	/*
	 * Note: the interface does not currently support
	 * RTE_ETH_RX_OFFLOAD_KEEP_CRC, please also consider ETHER_CRC_LEN
	 * when the adapter will be able to keep the CRC and subtract
	 * it to the length for all received packets:
	 * if (eth_dev->data->dev_conf.rxmode.offloads &
	 *     RTE_ETH_RX_OFFLOAD_KEEP_CRC)
	 *   rxq->crc_len = ETHER_CRC_LEN;
	 */

	/* Do not start queue with rte_eth_dev_start() */
	if (rx_conf->rx_deferred_start)
		rxq->flags |= IONIC_QCQ_F_DEFERRED;

	eth_dev->data->rx_queues[rx_queue_id] = rxq;

	return 0;
}

/*
 * Cleans one descriptor. Connects the filled mbufs into a chain.
 * Does not advance the tail index.
 */
static __rte_always_inline void
ionic_rx_clean_one(struct ionic_rx_qcq *rxq,
		struct ionic_rxq_comp *cq_desc,
		struct ionic_rx_service *rx_svc)
{
	struct ionic_queue *q = &rxq->qcq.q;
	struct rte_mbuf *rxm, *rxm_seg, *prev_rxm;
	struct ionic_rx_stats *stats = &rxq->stats;
	uint64_t pkt_flags = 0;
	uint32_t pkt_type;
	uint32_t left, i;
	uint16_t cq_desc_len;
	void **info;

	cq_desc_len = rte_le_to_cpu_16(cq_desc->len);

	info = IONIC_INFO_PTR(q, q->tail_idx);

	rxm = info[0];

	if (cq_desc->status) {
		stats->bad_cq_status++;
		return;
	}

	if (cq_desc_len > rxq->frame_size || cq_desc_len == 0) {
		stats->bad_len++;
		return;
	}

	info[0] = NULL;

	/* Set the mbuf metadata based on the cq entry */
	rxm->rearm_data[0] = rxq->rearm_data;
	rxm->pkt_len = cq_desc_len;
	rxm->data_len = RTE_MIN(rxq->hdr_seg_size, cq_desc_len);
	left = cq_desc_len - rxm->data_len;
	rxm->nb_segs = cq_desc->num_sg_elems + 1;
	prev_rxm = rxm;

	for (i = 1; i < rxm->nb_segs && left; i++) {
		rxm_seg = info[i];
		info[i] = NULL;

		/* Set the chained mbuf metadata */
		rxm_seg->rearm_data[0] = rxq->rearm_seg_data;
		rxm_seg->data_len = RTE_MIN(rxq->seg_size, left);
		left -= rxm_seg->data_len;

		/* Link the mbuf */
		prev_rxm->next = rxm_seg;
		prev_rxm = rxm_seg;
	}

	/* Terminate the mbuf chain */
	prev_rxm->next = NULL;

	/* RSS */
	pkt_flags |= RTE_MBUF_F_RX_RSS_HASH;
	rxm->hash.rss = rte_le_to_cpu_32(cq_desc->rss_hash);

	/* Vlan Strip */
	if (cq_desc->csum_flags & IONIC_RXQ_COMP_CSUM_F_VLAN) {
		pkt_flags |= RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
		rxm->vlan_tci = rte_le_to_cpu_16(cq_desc->vlan_tci);
	}

	/* Checksum */
	if (cq_desc->csum_flags & IONIC_RXQ_COMP_CSUM_F_CALC) {
		if (cq_desc->csum_flags & IONIC_RXQ_COMP_CSUM_F_IP_OK)
			pkt_flags |= RTE_MBUF_F_RX_IP_CKSUM_GOOD;
		else if (cq_desc->csum_flags & IONIC_RXQ_COMP_CSUM_F_IP_BAD)
			pkt_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;

		if ((cq_desc->csum_flags & IONIC_RXQ_COMP_CSUM_F_TCP_OK) ||
			(cq_desc->csum_flags & IONIC_RXQ_COMP_CSUM_F_UDP_OK))
			pkt_flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;
		else if ((cq_desc->csum_flags &
				IONIC_RXQ_COMP_CSUM_F_TCP_BAD) ||
				(cq_desc->csum_flags &
				IONIC_RXQ_COMP_CSUM_F_UDP_BAD))
			pkt_flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;
	}

	rxm->ol_flags = pkt_flags;

	/* Packet Type */
	switch (cq_desc->pkt_type_color & IONIC_RXQ_COMP_PKT_TYPE_MASK) {
	case IONIC_PKT_TYPE_IPV4:
		pkt_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4;
		break;
	case IONIC_PKT_TYPE_IPV6:
		pkt_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6;
		break;
	case IONIC_PKT_TYPE_IPV4_TCP:
		pkt_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 |
			RTE_PTYPE_L4_TCP;
		break;
	case IONIC_PKT_TYPE_IPV6_TCP:
		pkt_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 |
			RTE_PTYPE_L4_TCP;
		break;
	case IONIC_PKT_TYPE_IPV4_UDP:
		pkt_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 |
			RTE_PTYPE_L4_UDP;
		break;
	case IONIC_PKT_TYPE_IPV6_UDP:
		pkt_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 |
			RTE_PTYPE_L4_UDP;
		break;
	default:
		{
			struct rte_ether_hdr *eth_h = rte_pktmbuf_mtod(rxm,
				struct rte_ether_hdr *);
			uint16_t ether_type = eth_h->ether_type;
			if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
				pkt_type = RTE_PTYPE_L2_ETHER_ARP;
			else
				pkt_type = RTE_PTYPE_UNKNOWN;
			stats->mtods++;
			break;
		}
	}

	rxm->packet_type = pkt_type;

	rx_svc->rx_pkts[rx_svc->nb_rx] = rxm;
	rx_svc->nb_rx++;

	stats->packets++;
	stats->bytes += rxm->pkt_len;
}

/*
 * Fills one descriptor with mbufs. Does not advance the head index.
 */
static __rte_always_inline int
ionic_rx_fill_one(struct ionic_rx_qcq *rxq)
{
	struct ionic_queue *q = &rxq->qcq.q;
	struct rte_mbuf *rxm, *rxm_seg;
	struct ionic_rxq_desc *desc, *desc_base = q->base;
	struct ionic_rxq_sg_desc *sg_desc, *sg_desc_base = q->sg_base;
	rte_iova_t data_iova;
	uint32_t i;
	void **info;

	info = IONIC_INFO_PTR(q, q->head_idx);
	desc = &desc_base[q->head_idx];
	sg_desc = &sg_desc_base[q->head_idx];

	/* mbuf is unused => whole chain is unused */
	if (unlikely(info[0]))
		return 0;

	rxm = rte_mbuf_raw_alloc(rxq->mb_pool);
	if (unlikely(rxm == NULL)) {
		assert(0);
		return -ENOMEM;
	}

	info[0] = rxm;

	data_iova = rte_mbuf_data_iova_default(rxm);
	desc->addr = rte_cpu_to_le_64(data_iova);

	for (i = 1; i < q->num_segs; i++) {
		/* mbuf is unused => rest of the chain is unused */
		if (info[i])
			return 0;

		rxm_seg = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (rxm_seg == NULL) {
			assert(0);
			return -ENOMEM;
		}

		info[i] = rxm_seg;

		/* The data_off does not get set to 0 until later */
		data_iova = rxm_seg->buf_iova;
		sg_desc->elems[i - 1].addr = rte_cpu_to_le_64(data_iova);
	}

	return 0;
}

/*
 * Fills all descriptors with mbufs.
 */
static int __rte_cold
ionic_rx_fill(struct ionic_rx_qcq *rxq)
{
	struct ionic_queue *q = &rxq->qcq.q;
	uint32_t i;
	int err;

	for (i = 1; i < q->num_descs; i++) {
		err = ionic_rx_fill_one(rxq);
		if (err)
			return err;

		q->head_idx = Q_NEXT_TO_POST(q, 1);
	}

	ionic_q_flush(q);

	return 0;
}

/*
 * Perform one-time initialization of descriptor fields
 * which will not change for the life of the queue.
 */
static void __rte_cold
ionic_rx_init_descriptors(struct ionic_rx_qcq *rxq)
{
	struct ionic_queue *q = &rxq->qcq.q;
	struct ionic_rxq_desc *desc, *desc_base = q->base;
	struct ionic_rxq_sg_desc *sg_desc, *sg_desc_base = q->sg_base;
	uint32_t i, j;
	uint8_t opcode;

	opcode = (q->num_segs > 1) ?
		IONIC_RXQ_DESC_OPCODE_SG : IONIC_RXQ_DESC_OPCODE_SIMPLE;

	/*
	 * NB: Only the first segment needs to leave headroom (hdr_seg_size).
	 *     Later segments (seg_size) do not.
	 */
	for (i = 0; i < q->num_descs; i++) {
		desc = &desc_base[i];
		desc->len = rte_cpu_to_le_16(rxq->hdr_seg_size);
		desc->opcode = opcode;

		sg_desc = &sg_desc_base[i];
		for (j = 0; j < q->num_segs - 1u; j++)
			sg_desc->elems[j].len =
				rte_cpu_to_le_16(rxq->seg_size);
	}
}

/*
 * Start Receive Units for specified queue.
 */
int __rte_cold
ionic_dev_rx_queue_start(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id)
{
	uint8_t *rx_queue_state = eth_dev->data->rx_queue_state;
	struct ionic_rx_qcq *rxq;
	struct ionic_queue *q;
	int err;

	if (rx_queue_state[rx_queue_id] == RTE_ETH_QUEUE_STATE_STARTED) {
		IONIC_PRINT(DEBUG, "RX queue %u already started",
			rx_queue_id);
		return 0;
	}

	rxq = eth_dev->data->rx_queues[rx_queue_id];
	q = &rxq->qcq.q;

	rxq->frame_size = rxq->qcq.lif->frame_size - RTE_ETHER_CRC_LEN;

	/* Recalculate segment count based on MTU */
	q->num_segs = 1 +
		(rxq->frame_size + RTE_PKTMBUF_HEADROOM - 1) / rxq->seg_size;

	IONIC_PRINT(DEBUG, "Starting RX queue %u, %u descs, size %u segs %u",
		rx_queue_id, q->num_descs, rxq->frame_size, q->num_segs);

	ionic_rx_init_descriptors(rxq);

	err = ionic_lif_rxq_init(rxq);
	if (err)
		return err;

	/* Allocate buffers for descriptor rings */
	if (ionic_rx_fill(rxq) != 0) {
		IONIC_PRINT(ERR, "Could not alloc mbuf for queue:%d",
			rx_queue_id);
		return -1;
	}

	rx_queue_state[rx_queue_id] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

/*
 * Walk the CQ to find completed receive descriptors.
 * Any completed descriptor found is refilled.
 */
static __rte_always_inline void
ionic_rxq_service(struct ionic_rx_qcq *rxq, uint32_t work_to_do,
		struct ionic_rx_service *rx_svc)
{
	struct ionic_cq *cq = &rxq->qcq.cq;
	struct ionic_queue *q = &rxq->qcq.q;
	struct ionic_rxq_desc *q_desc_base = q->base;
	struct ionic_rxq_comp *cq_desc, *cq_desc_base = cq->base;
	uint32_t work_done = 0;

	cq_desc = &cq_desc_base[cq->tail_idx];

	while (color_match(cq_desc->pkt_type_color, cq->done_color)) {
		cq->tail_idx = Q_NEXT_TO_SRVC(cq, 1);

		if (cq->tail_idx == 0)
			cq->done_color = !cq->done_color;

		/* Prefetch 8 x 8B bufinfo */
		rte_prefetch0(IONIC_INFO_PTR(q, Q_NEXT_TO_SRVC(q, 8)));
		/* Prefetch 4 x 16B comp */
		rte_prefetch0(&cq_desc_base[Q_NEXT_TO_SRVC(cq, 4)]);
		/* Prefetch 4 x 16B descriptors */
		rte_prefetch0(&q_desc_base[Q_NEXT_TO_POST(q, 4)]);

		ionic_rx_clean_one(rxq, cq_desc, rx_svc);

		q->tail_idx = Q_NEXT_TO_SRVC(q, 1);

		(void)ionic_rx_fill_one(rxq);

		q->head_idx = Q_NEXT_TO_POST(q, 1);

		if (++work_done == work_to_do)
			break;

		cq_desc = &cq_desc_base[cq->tail_idx];
	}

	/* Update the queue indices and ring the doorbell */
	if (work_done)
		ionic_q_flush(q);
}

/*
 * Stop Receive Units for specified queue.
 */
int __rte_cold
ionic_dev_rx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t rx_queue_id)
{
	uint8_t *rx_queue_state = eth_dev->data->rx_queue_state;
	struct ionic_rx_stats *stats;
	struct ionic_rx_qcq *rxq;

	IONIC_PRINT(DEBUG, "Stopping RX queue %u", rx_queue_id);

	rxq = eth_dev->data->rx_queues[rx_queue_id];

	rx_queue_state[rx_queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;

	ionic_lif_rxq_deinit(rxq);

	/* Free all buffers from descriptor ring */
	ionic_rx_empty(rxq);

	stats = &rxq->stats;
	IONIC_PRINT(DEBUG, "RX queue %u pkts %ju mtod %ju",
		rxq->qcq.q.index, stats->packets, stats->mtods);

	return 0;
}

uint16_t
ionic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	struct ionic_rx_qcq *rxq = rx_queue;
	struct ionic_rx_service rx_svc;

	rx_svc.rx_pkts = rx_pkts;
	rx_svc.nb_rx = 0;

	ionic_rxq_service(rxq, nb_pkts, &rx_svc);

	return rx_svc.nb_rx;
}
