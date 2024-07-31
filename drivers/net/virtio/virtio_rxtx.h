/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _VIRTIO_RXTX_H_
#define _VIRTIO_RXTX_H_

#define RTE_PMD_VIRTIO_RX_MAX_BURST 64

struct virtnet_stats {
	uint64_t	packets;
	uint64_t	bytes;
	uint64_t	errors;
	uint64_t	multicast;
	uint64_t	broadcast;
	/* Size bins in array as RFC 2819, undersized [0], 64 [1], etc */
	uint64_t	size_bins[8];
};

struct virtnet_rx {
	struct rte_mbuf **sw_ring;  /**< RX software ring. */
	struct rte_mbuf *fake_mbuf; /**< dummy mbuf, for wraparound when processing RX ring. */
	uint64_t mbuf_initializer; /**< value to init mbufs. */
	struct rte_mempool *mpool; /**< mempool for mbuf allocation */

	/* Statistics */
	struct virtnet_stats stats;
};

struct virtnet_tx {
	const struct rte_memzone *hdr_mz; /**< memzone to populate hdr. */
	rte_iova_t hdr_mem;               /**< hdr for each xmit packet */

	struct virtnet_stats stats;       /* Statistics */
};

int virtio_rxq_vec_setup(struct virtnet_rx *rxvq);

static inline void
virtio_update_packet_stats(struct virtnet_stats *const stats, const struct rte_mbuf *const mbuf)
{
	uint32_t s = mbuf->pkt_len;
	const struct rte_ether_addr *ea = rte_pktmbuf_mtod(mbuf, const struct rte_ether_addr *);

	stats->bytes += s;

	if (s >= 1024) {
		stats->size_bins[6 + (s > 1518)]++;
	} else if (s <= 64) {
		stats->size_bins[s >> 6]++;
	} else {
		/* count zeros, and offset into correct bin */
		uint32_t bin = (sizeof(s) * 8) - rte_clz32(s) - 5;
		stats->size_bins[bin]++;
	}

	RTE_BUILD_BUG_ON(offsetof(struct virtnet_stats, broadcast) !=
			offsetof(struct virtnet_stats, multicast) + sizeof(uint64_t));
	if (rte_is_multicast_ether_addr(ea))
		(&stats->multicast)[rte_is_broadcast_ether_addr(ea)]++;
}

#endif /* _VIRTIO_RXTX_H_ */
