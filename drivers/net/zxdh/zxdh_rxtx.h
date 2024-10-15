/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_RXTX_H_
#define _ZXDH_RXTX_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_common.h>
#include <rte_mbuf_core.h>

struct virtnet_stats {
	uint64_t packets;
	uint64_t bytes;
	uint64_t errors;
	uint64_t multicast;
	uint64_t broadcast;
	uint64_t truncated_err;
	uint64_t size_bins[8]; /* Size bins in array as RFC 2819, undersized [0], 64 [1], etc */
};

struct virtnet_rx {
	struct virtqueue         *vq;

	/* dummy mbuf, for wraparound when processing RX ring. */
	struct rte_mbuf           fake_mbuf;

	uint64_t                  mbuf_initializer; /* value to init mbufs. */
	struct rte_mempool       *mpool;            /* mempool for mbuf allocation */
	uint16_t                  queue_id;         /* DPDK queue index. */
	uint16_t                  port_id;          /* Device port identifier. */
	struct virtnet_stats      stats;
	const struct rte_memzone *mz;               /* mem zone to populate RX ring. */
};

struct virtnet_tx {
	struct virtqueue         *vq;
	const struct rte_memzone *virtio_net_hdr_mz;  /* memzone to populate hdr. */
	rte_iova_t                virtio_net_hdr_mem; /* hdr for each xmit packet */
	uint16_t                  queue_id;           /* DPDK queue index. */
	uint16_t                  port_id;            /* Device port identifier. */
	struct virtnet_stats      stats;
	const struct rte_memzone *mz;                 /* mem zone to populate TX ring. */
};

#ifdef __cplusplus
}
#endif

#endif  /* _ZXDH_RXTX_H_ */
