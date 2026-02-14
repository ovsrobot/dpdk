/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <liburing.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <linux/virtio_net.h>

#include <rte_branch_prediction.h>
#include <rte_config.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_cksum.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_log.h>
#include <ethdev_driver.h>

#include "rtap.h"

/*
 * Since virtio net header is prepended to the mbuf,
 * the DPDK configuration should make sure that mbuf pools
 * are created to work.
 */
static_assert(RTE_PKTMBUF_HEADROOM >= sizeof(struct virtio_net_hdr),
	      "Pktmbuf headroom not big enough for virtio header");

/* Get the per-process file descriptor used transmit and receive */
static inline int
rtap_queue_fd(uint16_t port_id, uint16_t queue_id)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int *fds = dev->process_private;
	int fd = fds[queue_id];

	RTE_ASSERT(fd != -1);
	return fd;
}

/*
 * Add to submit queue a read of mbuf data.
 * For multi-segment mbuf's requires readv().
 * Return:
 *   -ENOSPC : no submit queue element available.
 *   1 : readv was used and no io_uring_submit was done.
 *   0 : regular read submitted, caller should call io_uring_submit
 *       later to batch.
 */
static inline int
rtap_rx_submit(struct rtap_rx_queue *rxq, int fd, struct rte_mbuf *mb)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rxq->io_ring);
	struct iovec iovs[IOV_MAX];
	uint16_t nsegs = mb->nb_segs;

	if (unlikely(sqe == NULL))
		return -ENOSPC;

	io_uring_sqe_set_data(sqe, mb);

	RTE_ASSERT(rte_pktmbuf_headroom(mb) >= sizeof(struct virtio_net_hdr));
	void *buf = rte_pktmbuf_mtod_offset(mb, void *, -sizeof(struct virtio_net_hdr));
	unsigned int nbytes = sizeof(struct virtio_net_hdr) + rte_pktmbuf_tailroom(mb);

	/* optimize for the case where packet fits in one mbuf */
	if (nsegs == 1) {
		io_uring_prep_read(sqe, fd, buf, nbytes, 0);
		/* caller will submit as batch */
		return 0;
	}

	RTE_ASSERT(nsegs > 0 && nsegs < IOV_MAX);

	iovs[0].iov_base = buf;
	iovs[0].iov_len = nbytes;

	for (uint16_t i = 1; i < nsegs; i++) {
		mb = mb->next;
		iovs[i].iov_base = rte_pktmbuf_mtod(mb, void *);
		iovs[i].iov_len = rte_pktmbuf_tailroom(mb);
	}
	io_uring_prep_readv(sqe, fd, iovs, nsegs, 0);

	/*
	 * For readv, need to submit now since iovs[] must be
	 * valid until submitted.
	 * io_uring_submit(3) returns the number of submitted submission
	 *  queue entries (on failure returns -errno).
	 */
	return io_uring_submit(&rxq->io_ring);
}

/* Allocates one or more mbuf's to be used for reading packets */
static struct rte_mbuf *
rtap_rx_alloc(struct rtap_rx_queue *rxq)
{
	const struct rte_eth_dev *dev = &rte_eth_devices[rxq->port_id];
	int buf_size = dev->data->mtu + RTE_ETHER_HDR_LEN;
	struct rte_mbuf *m = NULL;
	struct rte_mbuf **tail = &m;

	do {
		struct rte_mbuf *seg = rte_pktmbuf_alloc(rxq->mb_pool);
		if (unlikely(seg == NULL)) {
			rte_pktmbuf_free(m);
			return NULL;
		}
		*tail = seg;
		tail = &seg->next;
		if (seg != m)
			++m->nb_segs;

		buf_size -= rte_pktmbuf_tailroom(seg);
	} while (buf_size > 0);

	__rte_mbuf_sanity_check(m, 1);
	return m;
}

/*
 * When receiving multi-segment mbuf's need to adjust
 * the length of mbufs.
 */
static inline int
rtap_rx_adjust(struct rte_mbuf *mb, uint32_t len)
{
	struct rte_mbuf *seg;
	uint16_t count = 0;

	mb->pkt_len = len;

	/* Walk through mbuf chain and update the length of each segment */
	for (seg = mb; seg != NULL && len > 0; seg = seg->next) {
		uint16_t seg_len = RTE_MIN(len, rte_pktmbuf_tailroom(seg));

		seg->data_len = seg_len;
		count++;
		len -= seg_len;

		/* If length is zero, this is end of packet */
		if (len == 0) {
			/* Drop unused tail segments */
			if (seg->next != NULL) {
				struct rte_mbuf *tail = seg->next;
				seg->next = NULL;

				/* Free segments one by one to avoid nb_segs issues */
				while (tail != NULL) {
					struct rte_mbuf *next = tail->next;
					rte_pktmbuf_free_seg(tail);
					tail = next;
				}
			}

			mb->nb_segs = count;
			return 0;
		}
	}

	/* Packet was truncated - not enough mbuf space */
	return -1;
}

/*
 * Set the receive offload flags of received mbuf
 * based on the bits in the virtio network header
 */
static int
rtap_rx_offload(struct rte_mbuf *m, const struct virtio_net_hdr *hdr)
{
	uint32_t ptype;
	bool l4_supported = false;
	struct rte_net_hdr_lens hdr_lens;

	/* nothing to do */
	if (hdr->flags == 0 && hdr->gso_type == VIRTIO_NET_HDR_GSO_NONE)
		return 0;

	m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN;

	ptype = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);
	m->packet_type = ptype;
	if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP ||
	    (ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP ||
	    (ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_SCTP)
		l4_supported = true;

	if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		uint32_t hdrlen = hdr_lens.l2_len + hdr_lens.l3_len + hdr_lens.l4_len;
		if (hdr->csum_start <= hdrlen && l4_supported) {
			m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_NONE;
		} else {
			/* Unknown proto or tunnel, do sw cksum. */
			uint16_t csum = 0;

			if (rte_raw_cksum_mbuf(m, hdr->csum_start,
					       rte_pktmbuf_pkt_len(m) - hdr->csum_start,
					       &csum) < 0)
				return -EINVAL;
			if (likely(csum != 0xffff))
				csum = ~csum;

			uint32_t off = (uint32_t)hdr->csum_offset + hdr->csum_start;
			if (rte_pktmbuf_data_len(m) >= off + sizeof(uint16_t))
				*rte_pktmbuf_mtod_offset(m, uint16_t *, off) = csum;
		}
	} else if ((hdr->flags & VIRTIO_NET_HDR_F_DATA_VALID) && l4_supported) {
		m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;
	}

	/* GSO request, save required information in mbuf */
	if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		/* Check unsupported modes */
		if ((hdr->gso_type & VIRTIO_NET_HDR_GSO_ECN) || hdr->gso_size == 0)
			return -EINVAL;

		/* Update mss lengths in mbuf */
		m->tso_segsz = hdr->gso_size;
		switch (hdr->gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
		case VIRTIO_NET_HDR_GSO_TCPV6:
			m->ol_flags |= RTE_MBUF_F_RX_LRO | RTE_MBUF_F_RX_L4_CKSUM_NONE;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

uint16_t
rtap_rx_burst(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct rtap_rx_queue *rxq = queue;
	struct io_uring_cqe *cqe;
	unsigned int head, num_cqe = 0, num_sqe = 0;
	uint16_t num_rx = 0;
	uint32_t num_bytes = 0;
	int fd = rtap_queue_fd(rxq->port_id, rxq->queue_id);

	if (unlikely(nb_pkts == 0))
		return 0;

	io_uring_for_each_cqe(&rxq->io_ring, head, cqe) {
		struct rte_mbuf *mb = (void *)(uintptr_t)cqe->user_data;
		struct rte_mbuf *nmb = NULL;
		struct virtio_net_hdr *hdr = NULL;
		ssize_t len = cqe->res;
		int nsub;

		PMD_RX_LOG(DEBUG, "complete m=%p len=%zd", mb, len);

		num_cqe++;

		if (unlikely(len < (ssize_t)(sizeof(*hdr) + RTE_ETHER_HDR_LEN))) {
			if (len < 0)
				PMD_RX_LOG(ERR, "io_uring_read: %s", strerror(-len));
			else
				PMD_RX_LOG(ERR, "io_uring_read len %zd", len);
			rxq->rx_errors++;
			nmb = mb;
			goto resubmit;
		}

		/* virtio header is before packet data */
		hdr = rte_pktmbuf_mtod_offset(mb, struct virtio_net_hdr *, -sizeof(*hdr));
		len -= sizeof(*hdr);

		/* Replacement mbuf for resubmitting */
		nmb = rtap_rx_alloc(rxq);
		if (unlikely(nmb == NULL)) {
			struct rte_eth_dev *dev = &rte_eth_devices[rxq->port_id];

			PMD_RX_LOG(ERR, "Rx mbuf alloc failed");
			dev->data->rx_mbuf_alloc_failed++;
			rxq->xstats.mbuf_alloc_failed++;

			nmb = mb;	 /* Reuse original */
			goto resubmit;
		}

		if (mb->nb_segs == 1) {
			mb->data_len = len;
			mb->pkt_len = len;
		} else {
			if (unlikely(rtap_rx_adjust(mb, len) < 0)) {
				PMD_RX_LOG(ERR, "packet truncated: pkt_len=%u exceeds mbuf capacity",
					   mb->pkt_len);
				++rxq->rx_errors;
				rte_pktmbuf_free(mb);
				goto resubmit;
			}
		}

		if (unlikely(rtap_rx_offload(mb, hdr) < 0)) {
			PMD_RX_LOG(ERR, "invalid rx offload");
			++rxq->rx_errors;
			rte_pktmbuf_free(mb);
			goto resubmit;
		}

		mb->port = rxq->port_id;

		__rte_mbuf_sanity_check(mb, 1);
		rtap_rx_xstats_update(rxq, mb);
		num_bytes += mb->pkt_len;
		bufs[num_rx++] = mb;

resubmit:
		/* Submit the replacement mbuf */
		nsub = rtap_rx_submit(rxq, fd, nmb);
		if (unlikely(nsub < 0)) {
			/* Hope that later Rx can recover */
			PMD_RX_LOG(ERR, "io_uring no Rx sqe: %s", strerror(-nsub));
			rxq->rx_errors++;
			rte_pktmbuf_free(nmb);
			break;
		}

		if (nsub > 0)
			num_sqe = 0;
		else
			++num_sqe;

		if (num_rx == nb_pkts)
			break;
	}
	if (num_cqe > 0)
		io_uring_cq_advance(&rxq->io_ring, num_cqe);

	if (num_sqe > 0) {
		int n = io_uring_submit(&rxq->io_ring);
		if (unlikely(n < 0))
			PMD_LOG(ERR, "Rx io_uring submit failed: %s", strerror(-n));
		else if (unlikely(n != (int)num_sqe))
			PMD_RX_LOG(NOTICE, "Rx io_uring %d of %u resubmitted", n, num_sqe);
	}

	rxq->rx_packets += num_rx;
	rxq->rx_bytes += num_bytes;

	return num_rx;
}

/*
 * Cancel all pending io_uring operations and drain completions.
 * Uses IORING_ASYNC_CANCEL_ALL to cancel all operations at once.
 * Returns the number of mbufs freed.
 */
static unsigned int
rtap_cancel_all(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned int head, num_freed = 0;
	unsigned int ready;
	int ret;

	/* Cancel all pending operations using CANCEL_ALL flag */
	sqe = io_uring_get_sqe(ring);
	if (sqe != NULL) {
		/* IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_ANY cancels all ops */
		io_uring_prep_cancel(sqe, NULL,
				     IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_ANY);
		io_uring_sqe_set_data(sqe, NULL);
		ret = io_uring_submit(ring);
		if (ret < 0)
			PMD_LOG(ERR, "cancel submit failed: %s", strerror(-ret));
	}

	/*
	 * One blocking wait to let the kernel deliver the cancel CQE
	 * and the CQEs for all cancelled operations.
	 */
	io_uring_submit_and_wait(ring, 1);

	/*
	 * Drain all CQEs non-blocking.  Cancellation of many pending
	 * operations may produce CQEs in waves; keep polling until the
	 * CQ is empty.
	 */
	for (unsigned int retries = 0; retries < 10; retries++) {
		ready = io_uring_cq_ready(ring);
		if (ready == 0)
			break;

		io_uring_for_each_cqe(ring, head, cqe) {
			struct rte_mbuf *mb = (void *)(uintptr_t)cqe->user_data;

			/* Skip the cancel operation's own CQE (user_data = NULL) */
			if (mb != NULL) {
				rte_pktmbuf_free(mb);
				++num_freed;
			}
		}

		/* Advance past all processed CQEs */
		io_uring_cq_advance(ring, ready);
	}

	return num_freed;
}

int
rtap_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id, uint16_t nb_rx_desc,
		    unsigned int socket_id,
		    const struct rte_eth_rxconf *rx_conf __rte_unused,
		    struct rte_mempool *mb_pool)
{
	struct rte_mbuf **mbufs = NULL;
	unsigned int nsqe = 0;
	int fd = -1;

	PMD_LOG(DEBUG, "setup port %u queue %u rx_descriptors %u",
		dev->data->port_id, queue_id, nb_rx_desc);

	struct rtap_rx_queue *rxq = rte_zmalloc_socket(NULL, sizeof(*rxq),
						       RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL) {
		PMD_LOG(ERR, "rxq alloc failed");
		return -1;
	}

	rxq->mb_pool = mb_pool;
	rxq->port_id = dev->data->port_id;
	rxq->queue_id = queue_id;
	rxq->intr_fd = -1;
	dev->data->rx_queues[queue_id] = rxq;

	if (io_uring_queue_init(nb_rx_desc, &rxq->io_ring, 0) != 0) {
		PMD_LOG(ERR, "io_uring_queue_init failed: %s", strerror(errno));
		goto error_rxq_free;
	}

	/*
	 * Create an eventfd for Rx interrupt notification.
	 * io_uring will signal this fd whenever a CQE is posted,
	 * enabling power-aware applications to sleep until packets arrive.
	 */
	rxq->intr_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (rxq->intr_fd < 0) {
		PMD_LOG(ERR, "eventfd failed: %s", strerror(errno));
		goto error_iouring_exit;
	}

	if (io_uring_register_eventfd(&rxq->io_ring, rxq->intr_fd) < 0) {
		PMD_LOG(ERR, "io_uring_register_eventfd failed: %s", strerror(errno));
		goto error_eventfd_close;
	}

	mbufs = calloc(nb_rx_desc, sizeof(struct rte_mbuf *));
	if (mbufs == NULL) {
		PMD_LOG(ERR, "Rx mbuf pointer alloc failed");
		goto error_eventfd_close;
	}

	/* open shared tap fd maybe already setup */
	if (rtap_queue_open(dev, queue_id) < 0)
		goto error_bulk_free;

	fd = rtap_queue_fd(rxq->port_id, rxq->queue_id);

	for (uint16_t i = 0; i < nb_rx_desc; i++) {
		mbufs[i] = rtap_rx_alloc(rxq);
		if (mbufs[i] == NULL) {
			PMD_LOG(ERR, "Rx mbuf alloc buf failed");
			goto error_bulk_free;
		}

		int n = rtap_rx_submit(rxq, fd, mbufs[i]);
		if (n < 0) {
			PMD_LOG(ERR, "rtap_rx_submit failed: %s", strerror(-n));
			goto error_bulk_free;
		}

		/* If using readv() then n > 0 and all sqe's have been queued. */
		if (n > 0)
			nsqe = 0;
		else
			++nsqe;
	}

	if (nsqe > 0) {
		int n = io_uring_submit(&rxq->io_ring);
		if (n < 0) {
			PMD_LOG(ERR, "Rx io_uring submit failed: %s", strerror(-n));
			goto error_bulk_free;
		}
		if (n < (int)nsqe)
			PMD_LOG(NOTICE, "Rx io_uring partial submit %d of %u", n, nb_rx_desc);
	}

	free(mbufs);
	return 0;

error_bulk_free:
	/* some of the mbufs might be queued already */
	rtap_cancel_all(&rxq->io_ring);
	rtap_queue_close(dev, queue_id);
	free(mbufs);
error_eventfd_close:
	if (rxq->intr_fd >= 0) {
		close(rxq->intr_fd);
		rxq->intr_fd = -1;
	}
error_iouring_exit:
	io_uring_queue_exit(&rxq->io_ring);
error_rxq_free:
	rte_free(rxq);
	return -1;
}

void
rtap_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct rtap_rx_queue *rxq = dev->data->rx_queues[queue_id];

	if (rxq == NULL)
		return;

	if (rxq->intr_fd >= 0) {
		io_uring_unregister_eventfd(&rxq->io_ring);
		close(rxq->intr_fd);
		rxq->intr_fd = -1;
	}

	rtap_cancel_all(&rxq->io_ring);
	io_uring_queue_exit(&rxq->io_ring);

	rte_free(rxq);

	/* Close the shared TAP fd if the tx queue is already gone */
	if (queue_id >= dev->data->nb_tx_queues ||
	    dev->data->tx_queues[queue_id] == NULL)
		rtap_queue_close(dev, queue_id);
}

int
rtap_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id,
		    uint16_t nb_tx_desc, unsigned int socket_id,
		    const struct rte_eth_txconf *tx_conf)
{
	/* open shared tap fd maybe already setup */
	if (rtap_queue_open(dev, queue_id) < 0)
		return -1;

	struct rtap_tx_queue *txq = rte_zmalloc_socket(NULL, sizeof(*txq),
						       RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL) {
		PMD_LOG(ERR, "txq alloc failed");
		return -1;
	}

	txq->port_id = dev->data->port_id;
	txq->queue_id = queue_id;
	txq->free_thresh = tx_conf->tx_free_thresh;
	dev->data->tx_queues[queue_id] = txq;

	if (io_uring_queue_init(nb_tx_desc, &txq->io_ring, 0) != 0) {
		PMD_LOG(ERR, "io_uring_queue_init failed: %s", strerror(errno));
		rte_free(txq);
		return -1;
	}

	return 0;
}

static void
rtap_tx_cleanup(struct rtap_tx_queue *txq)
{
	struct io_uring_cqe *cqe;
	unsigned int head;
	unsigned int num_cqe = 0;

	io_uring_for_each_cqe(&txq->io_ring, head, cqe) {
		struct rte_mbuf *mb = (void *)(uintptr_t)cqe->user_data;

		++num_cqe;

		/* Skip CQEs with NULL user_data (e.g., cancel operations) */
		if (mb == NULL)
			continue;

		PMD_TX_LOG(DEBUG, " mbuf len %u result: %d", mb->pkt_len, cqe->res);
		txq->tx_errors += (cqe->res < 0);
		rte_pktmbuf_free(mb);
	}
	io_uring_cq_advance(&txq->io_ring, num_cqe);
}

void
rtap_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct rtap_tx_queue *txq = dev->data->tx_queues[queue_id];

	if (txq == NULL)
		return;

	/* First drain any completed TX operations */
	rtap_tx_cleanup(txq);

	/* Cancel all remaining pending operations and free mbufs */
	rtap_cancel_all(&txq->io_ring);
	io_uring_queue_exit(&txq->io_ring);

	rte_free(txq);

	/* Close the shared TAP fd if the rx queue is already gone */
	if (queue_id >= dev->data->nb_rx_queues ||
	    dev->data->rx_queues[queue_id] == NULL)
		rtap_queue_close(dev, queue_id);
}

/* Convert mbuf offload flags to virtio net header */
static void
rtap_tx_offload(struct virtio_net_hdr *hdr, const struct rte_mbuf *m)
{
	uint64_t csum_l4 = m->ol_flags & RTE_MBUF_F_TX_L4_MASK;
	uint16_t o_l23_len = (m->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) ?
			     m->outer_l2_len + m->outer_l3_len : 0;

	memset(hdr, 0, sizeof(*hdr));

	if (m->ol_flags & RTE_MBUF_F_TX_TCP_SEG)
		csum_l4 |= RTE_MBUF_F_TX_TCP_CKSUM;

	switch (csum_l4) {
	case RTE_MBUF_F_TX_UDP_CKSUM:
		hdr->csum_start = o_l23_len + m->l2_len + m->l3_len;
		hdr->csum_offset = offsetof(struct rte_udp_hdr, dgram_cksum);
		hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		break;

	case RTE_MBUF_F_TX_TCP_CKSUM:
		hdr->csum_start = o_l23_len + m->l2_len + m->l3_len;
		hdr->csum_offset = offsetof(struct rte_tcp_hdr, cksum);
		hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		break;
	}

	/* TCP Segmentation Offload */
	if (m->ol_flags & RTE_MBUF_F_TX_TCP_SEG) {
		hdr->gso_type = (m->ol_flags & RTE_MBUF_F_TX_IPV6) ?
			VIRTIO_NET_HDR_GSO_TCPV6 :
			VIRTIO_NET_HDR_GSO_TCPV4;
		hdr->gso_size = m->tso_segsz;
		hdr->hdr_len = o_l23_len + m->l2_len + m->l3_len + m->l4_len;
	}
}

/*
 * Transmit burst posts mbufs into the io_uring TAP file descriptor
 * by creating queue elements with write operation.
 *
 * The driver mimics the behavior of a real hardware NIC.
 *
 * If there is no space left in the io_uring then the driver will return the number of
 * mbuf's that were processed to that point. The application can then decide to retry
 * later or drop the unsent packets in case of backpressue.
 *
 * The transmit process puts the virtio header before the data. In some cases, a new mbuf
 * is required from same pool as original; but if that fails, the packet is not sent and
 * is silently dropped. This is to avoid situation where pool is so small that transmit
 * gets stuck when pool resources are very low.
 */
uint16_t
rtap_tx_burst(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct rtap_tx_queue *txq = queue;
	uint16_t i, num_tx = 0, num_pend = 0;
	uint32_t num_tx_bytes = 0;

	PMD_TX_LOG(DEBUG, "%d packets to xmit", nb_pkts);

	unsigned int space_desired = RTE_MAX(txq->free_thresh, nb_pkts);
	if (io_uring_sq_space_left(&txq->io_ring) < space_desired)
		rtap_tx_cleanup(txq);

	int fd = rtap_queue_fd(txq->port_id, txq->queue_id);

	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *mb = bufs[i];
		struct virtio_net_hdr *hdr;

		/* Use packet head room space for virtio header (if possible) */
		if (rte_mbuf_refcnt_read(mb) == 1 && RTE_MBUF_DIRECT(mb) &&
		    rte_pktmbuf_headroom(mb) >= sizeof(*hdr)) {
			hdr = rte_pktmbuf_mtod_offset(mb, struct virtio_net_hdr *, -sizeof(*hdr));
		} else {
			/* Need to chain a new mbuf to make room for virtio header */
			struct rte_mbuf *mh = rte_pktmbuf_alloc(mb->pool);
			if (unlikely(mh == NULL)) {
				PMD_TX_LOG(DEBUG, "mbuf pool exhausted on transmit");
				rte_pktmbuf_free(mb);
				++txq->tx_errors;
				continue;
			}

			/* The packet headroom should be available in newly allocated mbuf */
			RTE_ASSERT(rte_pktmbuf_headroom(mh) >= sizeof(*hdr));

			hdr = rte_pktmbuf_mtod_offset(mh, struct virtio_net_hdr *, -sizeof(*hdr));
			mh->next = mb;
			mh->nb_segs = mb->nb_segs + 1;
			mh->pkt_len = mb->pkt_len;
			mh->ol_flags = mb->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK;
			mb = mh;
		}

		struct io_uring_sqe *sqe = io_uring_get_sqe(&txq->io_ring);
		if (sqe == NULL) {
			/* Drop header mbuf if it was used */
			if (mb != bufs[i])
				rte_pktmbuf_free_seg(mb);
			break;	/* submit ring is full */
		}

		/* Note: transmit bytes does not include virtio header */
		++num_tx;
		num_tx_bytes += mb->pkt_len;

		io_uring_sqe_set_data(sqe, mb);
		rtap_tx_offload(hdr, mb);
		rtap_tx_xstats_update(txq, mb);

		PMD_TX_LOG(DEBUG, "write m=%p segs=%u", mb, mb->nb_segs);

		/* Start of data written to kernel includes virtio net header */
		void *buf = rte_pktmbuf_mtod_offset(mb, void *, -sizeof(*hdr));
		unsigned int nbytes = sizeof(struct virtio_net_hdr) + mb->data_len;

		if (mb->nb_segs == 1) {
			/* Single segment mbuf can go as write and batched */
			io_uring_prep_write(sqe, fd, buf, nbytes, 0);
			++num_pend;
		} else {
			/* Mult-segment mbuf needs scatter/gather */
			struct iovec iovs[IOV_MAX];
			unsigned int niov = mb->nb_segs;

			if (unlikely(niov > IOV_MAX)) {
				PMD_TX_LOG(ERR, "Tx nsegs %u > max %u",
					   niov, IOV_MAX);
				++txq->tx_errors;
				rte_pktmbuf_free(mb);
				continue;
			}

			iovs[0].iov_base = buf;
			iovs[0].iov_len = nbytes;

			for (unsigned int v = 1; v < niov; v++) {
				mb = mb->next;
				iovs[v].iov_base = rte_pktmbuf_mtod(mb, void *);
				iovs[v].iov_len = mb->data_len;
			}

			io_uring_prep_writev(sqe, fd, iovs, niov, 0);

			/*
			 * For writev, submit now since iovs[] is on the stack
			 * and must remain valid until submitted.
			 * This also submits any previously batched single-seg writes.
			 */
			int err = io_uring_submit(&txq->io_ring);
			if (unlikely(err < 0)) {
				PMD_TX_LOG(ERR, "Tx io_uring submit failed: %s", strerror(-err));
				++txq->tx_errors;
			}

			num_pend = 0;
		}
	}

	if (likely(num_pend > 0)) {
		int err = io_uring_submit(&txq->io_ring);
		if (unlikely(err < 0)) {
			PMD_LOG(ERR, "Tx io_uring submit failed: %s", strerror(-err));
			++txq->tx_errors;
		}
	}

	txq->tx_packets += num_tx;
	txq->tx_bytes += num_tx_bytes;

	return num_tx;
}
