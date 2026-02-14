/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#ifndef _RTAP_H_
#define _RTAP_H_

#include <errno.h>
#include <stdint.h>
#include <liburing.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_ether.h>

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
	int if_index;			/* interface index */
	int nlsk_fd;			/* netlink control socket */
	struct rte_ether_addr eth_addr; /* address assigned by kernel */
};

/* rtap_ethdev.c */
int rtap_queue_open(struct rte_eth_dev *dev, uint16_t queue_id);
void rtap_queue_close(struct rte_eth_dev *dev, uint16_t queue_id);

/* rtap_netlink.c */
int rtap_nl_open(unsigned int groups);
struct rte_eth_dev;
void rtap_nl_recv(int fd, struct rte_eth_dev *dev);
int rtap_nl_get_flags(int nlsk_fd, int if_index, unsigned int *flags);
int rtap_nl_change_flags(int nlsk_fd, int if_index,
			 unsigned int flags, unsigned int mask);
int rtap_nl_set_mtu(int nlsk_fd, int if_index, uint16_t mtu);
int rtap_nl_set_mac(int nlsk_fd, int if_index,
		    const struct rte_ether_addr *addr);
int rtap_nl_get_mac(int nlsk_fd, int if_index, struct rte_ether_addr *addr);
struct rtnl_link_stats64;
int rtap_nl_get_stats(int if_index, struct rtnl_link_stats64 *stats);

#endif /* _RTAP_H_ */
