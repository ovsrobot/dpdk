/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <liburing.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include <bus_vdev_driver.h>
#include <ethdev_driver.h>
#include <ethdev_vdev.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_kvargs.h>
#include <rte_log.h>

#define IORING_DEFAULT_BURST	64
#define IORING_NUM_BUFFERS	1024
#define IORING_MAX_QUEUES	128

#define IORING_TX_OFFLOAD	RTE_ETH_TX_OFFLOAD_VLAN_INSERT
#define IORING_RX_OFFLOAD	RTE_ETH_RX_OFFLOAD_VLAN_STRIP

static_assert(IORING_MAX_QUEUES <= RTE_MP_MAX_FD_NUM, "Max queues exceeds MP fd limit");

#define IORING_DEFAULT_IFNAME	"enio%d"
#define IORING_MP_KEY		"ioring_mp_send_fds"

RTE_LOG_REGISTER_DEFAULT(ioring_logtype, NOTICE);
#define RTE_LOGTYPE_IORING ioring_logtype
#define PMD_LOG(level, ...) RTE_LOG_LINE_PREFIX(level, IORING, "%s(): ", __func__, __VA_ARGS__)

#ifdef RTE_ETHDEV_DEBUG_RX
#define PMD_RX_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, IORING, "%s() rx: ", __func__, __VA_ARGS__)
#else
#define PMD_RX_LOG(...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
#define PMD_TX_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, IORING, "%s() tx: ", __func__, __VA_ARGS__)
#else
#define PMD_TX_LOG(...) do { } while (0)
#endif

#define IORING_IFACE_ARG	"iface"
#define IORING_PERSIST_ARG	"persist"

static const char * const valid_arguments[] = {
	IORING_IFACE_ARG,
	IORING_PERSIST_ARG,
	NULL
};

struct rx_queue {
	struct rte_mempool *mb_pool;	/* rx buffer pool */
	struct io_uring io_ring;	/* queue of posted read's */
	uint64_t offloads;
	uint16_t port_id;
	uint16_t queue_id;

	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t rx_nombuf;
	uint64_t rx_errors;
};

struct tx_queue {
	struct io_uring io_ring;
	uint64_t offloads;

	uint16_t port_id;
	uint16_t queue_id;
	uint16_t free_thresh;

	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t tx_errors;
};

struct pmd_internals {
	int keep_fd;			/* keep alive file descriptor */
	char ifname[IFNAMSIZ];		/* name assigned by kernel */
	struct rte_ether_addr eth_addr; /* address assigned by kernel */
};

static int
eth_dev_change_flags(struct rte_eth_dev *dev, uint16_t flags, uint16_t mask)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -errno;

	struct ifreq ifr = { };
	strlcpy(ifr.ifr_name, pmd->ifname, IFNAMSIZ);

	int ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if (ret < 0)
		goto error;

	/* NB: ifr.ifr_flags is type short */
	ifr.ifr_flags &= mask;
	ifr.ifr_flags |= flags;

	ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
error:
	close(sock);
	return (ret < 0) ? -errno : 0;
}

static int
eth_dev_get_flags(struct rte_eth_dev *dev, short *flags)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -errno;

	struct ifreq ifr = { };
	strlcpy(ifr.ifr_name, pmd->ifname, IFNAMSIZ);

	int ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if (ret == 0)
		*flags = ifr.ifr_flags;

	close(sock);
	return (ret < 0) ? -errno : 0;
}


/* Creates a new tap device, name returned in ifr */
static int
tap_open(const char *name, struct ifreq *ifr, uint8_t persist)
{
	static const char tun_dev[] = "/dev/net/tun";
	int tap_fd;

	tap_fd = open(tun_dev, O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (tap_fd < 0) {
		PMD_LOG(ERR, "Open %s failed: %s", tun_dev, strerror(errno));
		return -1;
	}

	int features = 0;
	if (ioctl(tap_fd, TUNGETFEATURES, &features) < 0) {
		PMD_LOG(ERR, "ioctl(TUNGETFEATURES) %s", strerror(errno));
		goto error;
	}

	int flags = IFF_TAP | IFF_MULTI_QUEUE | IFF_NO_PI;
	if ((features & flags) == 0) {
		PMD_LOG(ERR, "TUN features %#x missing support for %#x",
			features, features & flags);
		goto error;
	}

#ifdef IFF_NAPI
	/* If kernel supports using NAPI enable it */
	if (features & IFF_NAPI)
		flags |= IFF_NAPI;
#endif
	/*
	 * Sets the device name and packet format.
	 * Do not want the protocol information (PI)
	 */
	strlcpy(ifr->ifr_name, name, IFNAMSIZ);
	ifr->ifr_flags = flags;
	if (ioctl(tap_fd, TUNSETIFF, ifr) < 0) {
		PMD_LOG(ERR, "ioctl(TUNSETIFF) %s: %s",
			ifr->ifr_name, strerror(errno));
		goto error;
	}

	/* (Optional) keep the device after application exit */
	if (persist && ioctl(tap_fd, TUNSETPERSIST, 1) < 0) {
		PMD_LOG(ERR, "ioctl(TUNSETPERIST) %s: %s",
			ifr->ifr_name, strerror(errno));
		goto error;
	}

	return tap_fd;
error:
	close(tap_fd);
	return -1;
}


static int
eth_dev_set_link_up(struct rte_eth_dev *dev)
{
	return eth_dev_change_flags(dev, IFF_UP, 0);
}

static int
eth_dev_set_link_down(struct rte_eth_dev *dev)
{
	return eth_dev_change_flags(dev, 0, ~IFF_UP);
}

static int
eth_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	return eth_dev_change_flags(dev, IFF_PROMISC, ~0);
}

static int
eth_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	return eth_dev_change_flags(dev, 0, ~IFF_PROMISC);
}

static int
eth_dev_allmulticast_enable(struct rte_eth_dev *dev)
{
	return eth_dev_change_flags(dev, IFF_ALLMULTI, ~0);
}

static int
eth_dev_allmulticast_disable(struct rte_eth_dev *dev)
{
	return eth_dev_change_flags(dev, 0, ~IFF_ALLMULTI);
}

static int
eth_link_update(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct rte_eth_link *eth_link = &dev->data->dev_link;
	short flags = 0;

	if (eth_dev_get_flags(dev, &flags) < 0) {
		PMD_LOG(ERR, "ioctl(SIOCGIFFLAGS): %s", strerror(errno));
		return -1;
	}

	*eth_link = (struct rte_eth_link) {
		.link_speed = RTE_ETH_SPEED_NUM_UNKNOWN,
		.link_duplex = RTE_ETH_LINK_FULL_DUPLEX,
		.link_status = (flags & IFF_UP) ? RTE_ETH_LINK_UP : RTE_ETH_LINK_DOWN,
		.link_autoneg = RTE_ETH_LINK_FIXED,
	};
	return 0;
};

static int
eth_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -errno;

	struct ifreq ifr = { .ifr_mtu = mtu };

	strlcpy(ifr.ifr_name, pmd->ifname, IFNAMSIZ);

	int ret = ioctl(sock, SIOCSIFMTU, &ifr);
	if (ret < 0) {
		PMD_LOG(ERR, "ioctl(SIOCSIFMTU) failed: %s", strerror(errno));
		ret = -errno;
	}

	return ret;
}

static int
eth_dev_macaddr_set(struct rte_eth_dev *dev, struct rte_ether_addr *addr)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -errno;

	struct ifreq ifr = { };
	strlcpy(ifr.ifr_name, pmd->ifname, IFNAMSIZ);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(ifr.ifr_hwaddr.sa_data, addr, sizeof(*addr));

	int ret = ioctl(sock, SIOCSIFHWADDR, &ifr);
	if (ret < 0) {
		PMD_LOG(ERR, "ioctl(SIOCSIFHWADDR) failed: %s", strerror(errno));
		ret = -errno;
	}

	return ret;
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;
	eth_dev_set_link_up(dev);

	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	}

	return 0;
}

static int
eth_dev_stop(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
	eth_dev_set_link_down(dev);

	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	}

	return 0;
}

static int
eth_dev_configure(struct rte_eth_dev *dev)
{
	/* rx/tx must be paired */
	if (dev->data->nb_rx_queues != dev->data->nb_tx_queues)
		return -EINVAL;

	return 0;
}

static int
eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	dev_info->if_index = if_nametoindex(pmd->ifname);
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = RTE_ETHER_MAX_LEN;
	dev_info->max_rx_queues = IORING_MAX_QUEUES;
	dev_info->max_tx_queues = IORING_MAX_QUEUES;
	dev_info->min_rx_bufsize = 0;

	dev_info->default_rxportconf = (struct rte_eth_dev_portconf) {
		.burst_size = IORING_DEFAULT_BURST,
		.ring_size = IORING_NUM_BUFFERS,
		.nb_queues = 1,
	};

	return 0;
}

static int
eth_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		const struct rx_queue *rxq = dev->data->rx_queues[i];

		stats->ipackets += rxq->rx_packets;
		stats->ibytes += rxq->rx_bytes;
		stats->ierrors += rxq->rx_errors;
		stats->rx_nombuf += rxq->rx_nombuf;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_ipackets[i] = rxq->rx_packets;
			stats->q_ibytes[i] = rxq->rx_bytes;
		}
	}

	for (uint16_t i = 0; i < dev->data->nb_tx_queues; i++) {
		const struct tx_queue *txq = dev->data->tx_queues[i];

		stats->opackets += txq->tx_packets;
		stats->obytes += txq->tx_bytes;
		stats->oerrors += txq->tx_errors;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = txq->tx_packets;
			stats->q_obytes[i] = txq->tx_bytes;
		}
	}

	return 0;
}

static int
eth_dev_stats_reset(struct rte_eth_dev *dev)
{
	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		struct rx_queue *rxq = dev->data->rx_queues[i];

		rxq->rx_packets = 0;
		rxq->rx_bytes = 0;
		rxq->rx_nombuf = 0;
		rxq->rx_errors = 0;
	}

	for (uint16_t i = 0; i < dev->data->nb_tx_queues; i++) {
		struct tx_queue *txq = dev->data->tx_queues[i];

		txq->tx_packets = 0;
		txq->tx_bytes = 0;
		txq->tx_errors = 0;
	}
	return 0;
}

static int
eth_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	PMD_LOG(INFO, "Closing %s", pmd->ifname);

	int *fds = dev->process_private;
	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		if (fds[i] == -1)
			continue;
		close(fds[i]);
		fds[i] = -1;
	}

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	/* mac_addrs must not be freed alone because part of dev_private */
	dev->data->mac_addrs = NULL;

	if (pmd->keep_fd != -1) {
		close(pmd->keep_fd);
		pmd->keep_fd = -1;
	}
	return 0;
}

/* Setup another fd to TAP device for the queue */
static int
eth_queue_setup(struct rte_eth_dev *dev, const char *name, uint16_t queue_id)
{
	int *fds = dev->process_private;

	if (fds[queue_id] != -1)
		return 0;	/* already setup */

	struct ifreq ifr = { };
	int tap_fd = tap_open(name, &ifr, 0);
	if (tap_fd < 0) {
		PMD_LOG(ERR, "tap_open failed");
		return -1;
	}

	PMD_LOG(DEBUG, "opened %d for queue %u", tap_fd, queue_id);
	fds[queue_id] = tap_fd;
	return 0;
}

static int
eth_queue_fd(uint16_t port_id, uint16_t queue_id)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int *fds = dev->process_private;

	return fds[queue_id];
}

/* setup an submit queue to read mbuf */
static inline void
eth_rx_submit(struct rx_queue *rxq, int fd, struct rte_mbuf *mb)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&rxq->io_ring);

	if (unlikely(sqe == NULL)) {
		PMD_LOG(DEBUG, "io_uring no rx sqe");
		rxq->rx_errors++;
	} else {
		void *base = rte_pktmbuf_mtod(mb, void *);
		size_t len = mb->buf_len;

		io_uring_prep_read(sqe, fd, base, len, 0);
		io_uring_sqe_set_data(sqe, mb);
	}
}

static uint16_t
eth_ioring_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct rx_queue *rxq = queue;
	struct io_uring_cqe *cqe;
	unsigned int head, num_cqe = 0;
	uint16_t num_rx = 0;
	uint32_t num_bytes = 0;
	int fd = eth_queue_fd(rxq->port_id, rxq->queue_id);

	io_uring_for_each_cqe(&rxq->io_ring, head, cqe) {
		struct rte_mbuf *mb = (void *)(uintptr_t)cqe->user_data;
		ssize_t len = cqe->res;

		PMD_RX_LOG(DEBUG, "cqe %u len %zd", num_cqe, len);
		num_cqe++;

		if (unlikely(len < RTE_ETHER_HDR_LEN)) {
			if (len < 0)
				PMD_LOG(ERR, "io_uring_read: %s", strerror(-len));
			else
				PMD_LOG(ERR, "io_uring_read missing hdr");

			rxq->rx_errors++;
			goto resubmit;
		}

		struct rte_mbuf *nmb = rte_pktmbuf_alloc(rxq->mb_pool);
		if (unlikely(nmb == 0)) {
			PMD_LOG(DEBUG, "Rx mbuf alloc failed");
			++rxq->rx_nombuf;
			goto resubmit;
		}

		if (rxq->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
			rte_vlan_strip(mb);

		mb->pkt_len = len;
		mb->data_len = len;
		mb->port = rxq->port_id;
		__rte_mbuf_sanity_check(mb, 1);

		num_bytes += len;
		bufs[num_rx++] = mb;

		mb = nmb;
resubmit:
		eth_rx_submit(rxq, fd, mb);

		if (num_rx == nb_pkts)
			break;
	}
	io_uring_cq_advance(&rxq->io_ring, num_cqe);

	rxq->rx_packets += num_rx;
	rxq->rx_bytes += num_bytes;
	return num_rx;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id, uint16_t nb_rx_desc,
		   unsigned int socket_id, const struct rte_eth_rxconf *rx_conf,
		   struct rte_mempool *mb_pool)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	PMD_LOG(DEBUG, "setup port %u queue %u rx_descriptors %u",
		dev->data->port_id, queue_id, nb_rx_desc);

	/* open shared tap fd maybe already setup */
	if (eth_queue_setup(dev, pmd->ifname, queue_id) < 0)
		return -1;

	struct rx_queue *rxq = rte_zmalloc_socket(NULL, sizeof(*rxq),
						  RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL) {
		PMD_LOG(ERR, "rxq alloc failed");
		return -1;
	}

	rxq->offloads = rx_conf->offloads;
	rxq->mb_pool = mb_pool;
	rxq->port_id = dev->data->port_id;
	rxq->queue_id = queue_id;
	dev->data->rx_queues[queue_id] = rxq;

	struct rte_mbuf *mbufs[nb_rx_desc];
	if (rte_pktmbuf_alloc_bulk(mb_pool, mbufs, nb_rx_desc) < 0) {
		PMD_LOG(ERR, "Rx mbuf alloc %u bufs failed", nb_rx_desc);
		return -1;
	}

	if (io_uring_queue_init(nb_rx_desc, &rxq->io_ring, 0) != 0) {
		PMD_LOG(ERR, "io_uring_queue_init failed: %s", strerror(errno));
		goto error;
	}

	int fd = eth_queue_fd(rxq->port_id, rxq->queue_id);

	for (uint16_t i = 0; i < nb_rx_desc; i++) {
		struct rte_mbuf *mb = mbufs[i];

		eth_rx_submit(rxq, fd, mb);
	}

	io_uring_submit(&rxq->io_ring);
	return 0;

error:
	rte_pktmbuf_free_bulk(mbufs, nb_rx_desc);
	return -1;
}

static void
eth_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct rx_queue *rxq = dev->data->rx_queues[queue_id];

	struct io_uring_sqe *sqe = io_uring_get_sqe(&rxq->io_ring);
	if (sqe == NULL) {
		PMD_LOG(ERR, "io_uring_get_sqe failed: %s", strerror(errno));
	} else {
		io_uring_prep_cancel(sqe, NULL, IORING_ASYNC_CANCEL_ANY);
		io_uring_submit_and_wait(&rxq->io_ring, 1);
	}

	io_uring_queue_exit(&rxq->io_ring);
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id,
		   uint16_t nb_tx_desc, unsigned int socket_id,
		   const struct rte_eth_txconf *tx_conf)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	/* open shared tap fd maybe already setup */
	if (eth_queue_setup(dev, pmd->ifname, queue_id) < 0)
		return -1;

	struct tx_queue *txq = rte_zmalloc_socket(NULL, sizeof(*txq), RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL) {
		PMD_LOG(ERR, "txq alloc failed");
		return -1;
	}

	txq->port_id = dev->data->port_id;
	txq->queue_id = queue_id;
	txq->offloads = tx_conf->offloads;
	txq->free_thresh = tx_conf->tx_free_thresh;
	dev->data->tx_queues[queue_id] = txq;

	if (io_uring_queue_init(nb_tx_desc, &txq->io_ring, 0) != 0) {
		PMD_LOG(ERR, "io_uring_queue_init failed: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static void
eth_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct tx_queue *txq = dev->data->tx_queues[queue_id];

	struct io_uring_sqe *sqe = io_uring_get_sqe(&txq->io_ring);
	if (sqe == NULL) {
		PMD_LOG(ERR, "io_uring_get_sqe failed: %s", strerror(errno));
	} else {
		io_uring_prep_cancel(sqe, NULL, IORING_ASYNC_CANCEL_ANY);
		io_uring_submit_and_wait(&txq->io_ring, 1);
	}

	io_uring_queue_exit(&txq->io_ring);
}

static void
eth_ioring_tx_cleanup(struct tx_queue *txq)
{
	struct io_uring_cqe *cqe;
	unsigned int head;
	unsigned int tx_done = 0;
	uint64_t tx_bytes = 0;

	io_uring_for_each_cqe(&txq->io_ring, head, cqe) {
		struct rte_mbuf *mb = (void *)(uintptr_t)cqe->user_data;

		PMD_TX_LOG(DEBUG, " mbuf len %u result: %d", mb->pkt_len, cqe->res);
		if (unlikely(cqe->res < 0)) {
			++txq->tx_errors;
		} else {
			++tx_done;
			tx_bytes += mb->pkt_len;
		}

		rte_pktmbuf_free(mb);
	}
	io_uring_cq_advance(&txq->io_ring, tx_done);

	txq->tx_packets += tx_done;
	txq->tx_bytes += tx_bytes;
}

static uint16_t
eth_ioring_tx_prepare(void *tx_queue __rte_unused, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint16_t nb_tx;
	int error;

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		struct rte_mbuf *m = tx_pkts[nb_tx];

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
		error = rte_validate_tx_offload(m);
		if (unlikely(error)) {
			rte_errno = -error;
			break;
		}
#endif
		/* Do VLAN tag insertion */
		if (unlikely(m->ol_flags & RTE_MBUF_F_TX_VLAN)) {
			error = rte_vlan_insert(&m);
			/* rte_vlan_insert() may change pointer */
			tx_pkts[nb_tx] = m;

			if (unlikely(error)) {
				rte_errno = -error;
				break;
			}
		}
	}

	return nb_tx;
}

static uint16_t
eth_ioring_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct tx_queue *txq = queue;
	uint16_t num_tx;

	if (unlikely(nb_pkts == 0))
		return 0;

	PMD_TX_LOG(DEBUG, "%d packets to xmit", nb_pkts);

	if (io_uring_sq_space_left(&txq->io_ring) < txq->free_thresh)
		eth_ioring_tx_cleanup(txq);

	int fd = eth_queue_fd(txq->port_id, txq->queue_id);

	for (num_tx = 0; num_tx < nb_pkts; num_tx++) {
		struct rte_mbuf *mb = bufs[num_tx];

		struct io_uring_sqe *sqe = io_uring_get_sqe(&txq->io_ring);
		if (sqe == NULL)
			break;	/* submit ring is full */

		io_uring_sqe_set_data(sqe, mb);

		if (rte_mbuf_refcnt_read(mb) == 1 &&
		    RTE_MBUF_DIRECT(mb) && mb->nb_segs == 1) {
			void *base = rte_pktmbuf_mtod(mb, void *);
			io_uring_prep_write(sqe, fd, base, mb->pkt_len, 0);

			PMD_TX_LOG(DEBUG, "tx mbuf: %p submit", mb);
		} else {
			PMD_LOG(ERR, "Can't do mbuf without space yet!");
			++txq->tx_errors;
			continue;
		}
	}
	if (num_tx > 0)
		io_uring_submit(&txq->io_ring);

	return num_tx;
}

static const struct eth_dev_ops ops = {
	.dev_start		= eth_dev_start,
	.dev_stop		= eth_dev_stop,
	.dev_configure		= eth_dev_configure,
	.dev_infos_get		= eth_dev_info,
	.dev_close		= eth_dev_close,
	.link_update		= eth_link_update,
	.dev_set_link_up	= eth_dev_set_link_up,
	.dev_set_link_down	= eth_dev_set_link_down,
	.mac_addr_set		= eth_dev_macaddr_set,
	.mtu_set		= eth_dev_mtu_set,
	.promiscuous_enable	= eth_dev_promiscuous_enable,
	.promiscuous_disable	= eth_dev_promiscuous_disable,
	.allmulticast_enable	= eth_dev_allmulticast_enable,
	.allmulticast_disable	= eth_dev_allmulticast_disable,
	.stats_get              = eth_dev_stats_get,
	.stats_reset            = eth_dev_stats_reset,
	.rx_queue_setup		= eth_rx_queue_setup,
	.rx_queue_release	= eth_rx_queue_release,
	.tx_queue_setup		= eth_tx_queue_setup,
	.tx_queue_release	= eth_tx_queue_release,
};

static int
ioring_create(struct rte_eth_dev *dev, const char *tap_name, uint8_t persist)
{
	struct rte_eth_dev_data *data = dev->data;
	struct pmd_internals *pmd = data->dev_private;

	pmd->keep_fd = -1;

	data->dev_flags = RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
	dev->dev_ops = &ops;

	/* Get the initial fd used to keep the tap device around */
	struct ifreq ifr = { };
	pmd->keep_fd = tap_open(tap_name, &ifr, persist);
	if (pmd->keep_fd < 0)
		goto error;

	strlcpy(pmd->ifname, ifr.ifr_name, IFNAMSIZ);

	/* Read the MAC address assigned by the kernel */
	if (ioctl(pmd->keep_fd, SIOCGIFHWADDR, &ifr) < 0) {
		PMD_LOG(ERR, "Unable to get MAC address for %s: %s",
			ifr.ifr_name, strerror(errno));
		goto error;
	}
	memcpy(&pmd->eth_addr, &ifr.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);
	data->mac_addrs = &pmd->eth_addr;

	/* Detach this instance, not used for traffic */
	ifr.ifr_flags = IFF_DETACH_QUEUE;
	if (ioctl(pmd->keep_fd, TUNSETQUEUE, &ifr) < 0) {
		PMD_LOG(ERR, "Unable to detach keep-alive queue for %s: %s",
			ifr.ifr_name, strerror(errno));
		goto error;
	}

	PMD_LOG(DEBUG, "%s setup", ifr.ifr_name);

	dev->rx_pkt_burst = eth_ioring_rx;
	dev->tx_pkt_prepare = eth_ioring_tx_prepare;
	dev->tx_pkt_burst = eth_ioring_tx;

	return 0;

error:
	if (pmd->keep_fd != -1)
		close(pmd->keep_fd);
	return -1;
}

static int
parse_iface_arg(const char *key __rte_unused, const char *value, void *extra_args)
{
	char *name = extra_args;

	/* must not be null string */
	if (name == NULL || name[0] == '\0' ||
	    strnlen(name, IFNAMSIZ) == IFNAMSIZ)
		return -EINVAL;

	strlcpy(name, value, IFNAMSIZ);
	return 0;
}

/* Secondary process requests rxq fds from primary. */
static int
ioring_request_fds(const char *name, struct rte_eth_dev *dev)
{
	struct rte_mp_msg request = { };

	strlcpy(request.name, IORING_MP_KEY, sizeof(request.name));
	strlcpy((char *)request.param, name, RTE_MP_MAX_PARAM_LEN);
	request.len_param = strlen(name);

	/* Send the request and receive the reply */
	PMD_LOG(DEBUG, "Sending multi-process IPC request for %s", name);

	struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
	struct rte_mp_reply replies;
	int ret = rte_mp_request_sync(&request, &replies, &timeout);
	if (ret < 0 || replies.nb_received != 1) {
		PMD_LOG(ERR, "Failed to request fds from primary: %s",
			rte_strerror(rte_errno));
		return -1;
	}

	struct rte_mp_msg *reply = replies.msgs;
	PMD_LOG(DEBUG, "Received multi-process IPC reply for %s", name);
	if (dev->data->nb_rx_queues != reply->num_fds) {
		PMD_LOG(ERR, "Incorrect number of fds received: %d != %d",
			reply->num_fds, dev->data->nb_rx_queues);
		return -EINVAL;
	}

	int *fds = dev->process_private;
	for (int i = 0; i < reply->num_fds; i++)
		fds[i] = reply->fds[i];

	free(reply);
	return 0;
}

/* Primary process sends rxq fds to secondary. */
static int
ioring_mp_send_fds(const struct rte_mp_msg *request, const void *peer)
{
	const char *request_name = (const char *)request->param;

	PMD_LOG(DEBUG, "Received multi-process IPC request for %s", request_name);

	/* Find the requested port */
	struct rte_eth_dev *dev = rte_eth_dev_get_by_name(request_name);
	if (!dev) {
		PMD_LOG(ERR, "Failed to get port id for %s", request_name);
		return -1;
	}

	/* Populate the reply with the xsk fd for each queue */
	struct rte_mp_msg reply = { };
	if (dev->data->nb_rx_queues > RTE_MP_MAX_FD_NUM) {
		PMD_LOG(ERR, "Number of rx queues (%d) exceeds max number of fds (%d)",
			   dev->data->nb_rx_queues, RTE_MP_MAX_FD_NUM);
		return -EINVAL;
	}

	int *fds = dev->process_private;
	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++)
		reply.fds[reply.num_fds++] = fds[i];

	/* Send the reply */
	strlcpy(reply.name, request->name, sizeof(reply.name));
	strlcpy((char *)reply.param, request_name, RTE_MP_MAX_PARAM_LEN);
	reply.len_param = strlen(request_name);

	PMD_LOG(DEBUG, "Sending multi-process IPC reply for %s", request_name);
	if (rte_mp_reply(&reply, peer) < 0) {
		PMD_LOG(ERR, "Failed to reply to multi-process IPC request");
		return -1;
	}
	return 0;
}

static int
ioring_probe(struct rte_vdev_device *vdev)
{
	const char *name = rte_vdev_device_name(vdev);
	const char *params = rte_vdev_device_args(vdev);
	struct rte_kvargs *kvlist = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	int *fds = NULL;
	char tap_name[IFNAMSIZ] = IORING_DEFAULT_IFNAME;
	uint8_t persist = 0;
	int ret;

	PMD_LOG(INFO, "Initializing %s", name);

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		struct rte_eth_dev *eth_dev;

		eth_dev = rte_eth_dev_attach_secondary(name);
		if (!eth_dev) {
			PMD_LOG(ERR, "Failed to probe %s", name);
			return -1;
		}
		eth_dev->dev_ops = &ops;
		eth_dev->device = &vdev->device;

		if (!rte_eal_primary_proc_alive(NULL)) {
			PMD_LOG(ERR, "Primary process is missing");
			return -1;
		}

		fds  = calloc(RTE_MAX_QUEUES_PER_PORT, sizeof(int));
		if (fds == NULL) {
			PMD_LOG(ERR, "Failed to alloc memory for process private");
			return -1;
		}

		eth_dev->process_private = fds;

		if (ioring_request_fds(name, eth_dev))
			return -1;

		rte_eth_dev_probing_finish(eth_dev);
		return 0;
	}

	if (params != NULL) {
		kvlist = rte_kvargs_parse(params, valid_arguments);
		if (kvlist == NULL)
			return -1;

		if (rte_kvargs_count(kvlist, IORING_IFACE_ARG) == 1) {
			ret = rte_kvargs_process_opt(kvlist, IORING_IFACE_ARG,
						     &parse_iface_arg, tap_name);
			if (ret < 0)
				goto error;
		}

		if (rte_kvargs_count(kvlist, IORING_PERSIST_ARG) == 1)
			persist = 1;
	}

	/* Per-queue tap fd's (for primary process) */
	fds = calloc(RTE_MAX_QUEUES_PER_PORT, sizeof(int));
	if (fds == NULL) {
		PMD_LOG(ERR, "Unable to allocate fd array");
		return -1;
	}
	for (unsigned int i = 0; i < RTE_MAX_QUEUES_PER_PORT; i++)
		fds[i] = -1;

	eth_dev = rte_eth_vdev_allocate(vdev, sizeof(struct pmd_internals));
	if (eth_dev == NULL) {
		PMD_LOG(ERR, "%s Unable to allocate device struct", tap_name);
		goto error;
	}

	eth_dev->data->dev_flags = RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
	eth_dev->dev_ops = &ops;
	eth_dev->process_private = fds;

	if (ioring_create(eth_dev, tap_name, persist) < 0)
		goto error;

	/* register the MP server on the first device */
	static unsigned int ioring_dev_count;
	if (ioring_dev_count == 0) {
		if (rte_mp_action_register(IORING_MP_KEY, ioring_mp_send_fds) < 0) {
			PMD_LOG(ERR, "Failed to register multi-process callback: %s",
				rte_strerror(rte_errno));
			goto error;
		}
	}
	++ioring_dev_count;
	rte_eth_dev_probing_finish(eth_dev);
	return 0;

error:
	if (eth_dev != NULL)
		rte_eth_dev_release_port(eth_dev);
	free(fds);
	rte_kvargs_free(kvlist);
	return -1;
}

static int
ioring_remove(struct rte_vdev_device *dev)
{
	struct rte_eth_dev *eth_dev;

	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
	if (eth_dev == NULL)
		return 0;

	eth_dev_close(eth_dev);
	rte_eth_dev_release_port(eth_dev);
	return 0;
}

static struct rte_vdev_driver pmd_ioring_drv = {
	.probe = ioring_probe,
	.remove = ioring_remove,
};

RTE_PMD_REGISTER_VDEV(net_ioring, pmd_ioring_drv);
RTE_PMD_REGISTER_ALIAS(net_ioring, eth_ioring);
RTE_PMD_REGISTER_PARAM_STRING(net_ioring, IORING_IFACE_ARG "=<string> ");
