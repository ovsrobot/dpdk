/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#ifndef _RTAP_H_
#define _RTAP_H_

#include <assert.h>
#include <unistd.h>
#include <net/if.h>
#include <liburing.h>
#include <linux/virtio_net.h>

#include <ethdev_driver.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_log.h>


extern int rtap_logtype;
#define RTE_LOGTYPE_RTAP rtap_logtype
#define PMD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, RTAP, "%s(): ", __func__, __VA_ARGS__)

#define PMD_LOG_ERRNO(level, fmt, ...) \
	RTE_LOG_LINE(level, RTAP, "%s(): " fmt ": %s", __func__, ## __VA_ARGS__, strerror(errno))

#ifdef RTE_ETHDEV_DEBUG_RX
#define PMD_RX_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, RTAP, "%s() rx: ", __func__, __VA_ARGS__)
#else
#define PMD_RX_LOG(...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
#define PMD_TX_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, RTAP, "%s() tx: ", __func__, __VA_ARGS__)
#else
#define PMD_TX_LOG(...) do { } while (0)
#endif

struct rtap_rx_queue {
	struct rte_mempool *mb_pool;	/* rx buffer pool */
	struct io_uring io_ring;	/* queue of posted read's */
	uint16_t port_id;
	uint16_t queue_id;

	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t rx_errors;
} __rte_cache_aligned;

struct rtap_tx_queue {
	struct io_uring io_ring;
	uint16_t port_id;
	uint16_t queue_id;
	uint16_t free_thresh;

	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t tx_errors;
} __rte_cache_aligned;

struct rtap_pmd {
	int keep_fd;			/* keep alive file descriptor */
	struct rte_intr_handle *intr_handle; /* LSC interrupt handle */
	char ifname[IFNAMSIZ];		/* name assigned by kernel */
	struct rte_ether_addr eth_addr; /* address assigned by kernel */

	uint64_t rx_drop_base;		/* value of rx_dropped when reset */
};

/* rtap_ethdev.c */
int rtap_queue_open(struct rte_eth_dev *dev, uint16_t queue_id);
void rtap_queue_close(struct rte_eth_dev *dev, uint16_t queue_id);
int rtap_link_update(struct rte_eth_dev *dev, int wait_to_complete);

/* rtap_rxtx.c */
uint16_t rtap_rx_burst(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);
uint16_t rtap_tx_burst(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);
int rtap_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id,
			uint16_t nb_rx_desc, unsigned int socket_id,
			const struct rte_eth_rxconf *rx_conf,
			struct rte_mempool *mb_pool);
void rtap_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id);
int rtap_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id,
			uint16_t nb_tx_desc, unsigned int socket_id,
			const struct rte_eth_txconf *tx_conf);
void rtap_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id);

/* rtap_intr.c */
int rtap_lsc_set(struct rte_eth_dev *dev, int set);

#endif /* _RTAP_H_ */
