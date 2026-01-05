/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 FreeBSD Foundation
 * Originally based upon librte_pmd_af_packet code:
 * Copyright(c) 2014 John W. Linville <linville@tuxdriver.com>
 * Copyright(c) 2010-2015 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 * All rights reserved.
 */

#include <rte_common.h>
#include <rte_string_fns.h>
#include <rte_mbuf.h>
#include <ethdev_driver.h>
#include <ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_kvargs.h>
#include <bus_vdev_driver.h>

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#define ETH_BPF_IFACE_ARG		"iface"
#define ETH_BPF_NUM_Q_ARG		"qpairs"
#define ETH_BPF_BUFSIZE_ARG		"bufsz"
#define ETH_BPF_ZEROCOPY_ARG		"zerocopy"

#define DFLT_BUF_SIZE		(1 << 16)	/* 64KB default buffer */
#define MAX_BPF_DEVICES		256

/*
 * Zero-copy BPF support
 */
#if defined(BIOCSETZBUF) && defined(BPF_BUFMODE_ZBUF)
#define HAVE_ZEROCOPY_BPF
#endif

struct __rte_cache_aligned pkt_rx_queue {
	int fd;

	uint8_t *buffer;
	unsigned int bufsize;
	uint8_t *bp;		/* current buffer pointer */
	unsigned int cc;	/* bytes remaining in buffer */

#ifdef HAVE_ZEROCOPY_BPF
	uint8_t *zbuf1;
	uint8_t *zbuf2;
	uint8_t *zbuffer;	/* current zero-copy buffer */
	unsigned int zbufsize;
	struct bpf_zbuf_header *bzh;
	uint8_t zerocopy;
#endif

	struct rte_mempool *mb_pool;
	uint16_t in_port;
	uint8_t vlan_strip;

	volatile unsigned long rx_pkts;
	volatile unsigned long rx_bytes;
	volatile unsigned long rx_nombuf;
	volatile unsigned long rx_dropped_pkts;
};

struct __rte_cache_aligned pkt_tx_queue {
	int fd;
	unsigned int bufsize;

	volatile unsigned long tx_pkts;
	volatile unsigned long err_pkts;
	volatile unsigned long tx_bytes;
};

struct pmd_internals {
	unsigned nb_queues;

	int if_index;
	char *if_name;
	struct rte_ether_addr eth_addr;

	unsigned int bufsize;
#ifdef HAVE_ZEROCOPY_BPF
	uint8_t zerocopy;
#endif

	struct pkt_rx_queue *rx_queue;
	struct pkt_tx_queue *tx_queue;
	uint8_t vlan_strip;
};

static const char *valid_arguments[] = {
	ETH_BPF_IFACE_ARG,
	ETH_BPF_NUM_Q_ARG,
	ETH_BPF_BUFSIZE_ARG,
	ETH_BPF_ZEROCOPY_ARG,
	NULL
};

static struct rte_eth_link pmd_link = {
	.link_speed = RTE_ETH_SPEED_NUM_10G,
	.link_duplex = RTE_ETH_LINK_FULL_DUPLEX,
	.link_status = RTE_ETH_LINK_DOWN,
	.link_autoneg = RTE_ETH_LINK_FIXED,
};

RTE_LOG_REGISTER_DEFAULT(bpf_logtype, NOTICE);
#define RTE_LOGTYPE_BPF bpf_logtype

#define PMD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, BPF, "%s(): ", __func__, __VA_ARGS__)

#define PMD_LOG_ERRNO(level, fmt, ...) \
	RTE_LOG_LINE(level, BPF, "%s(): " fmt ":%s", __func__, \
		## __VA_ARGS__, strerror(errno))

#ifdef HAVE_ZEROCOPY_BPF
/*
 * Zero-copy BPF buffer routines to check for and acknowledge BPF data in
 * shared memory buffers.
 *
 * Note: We use __atomic builtins here because the kernel's bpf_zbuf_header
 * structure uses regular volatile integers, not C11 _Atomic types. The
 * __atomic builtins work with any integer type while providing the needed
 * memory ordering semantics.
 */
static int
bpf_next_zbuf_shm(struct pkt_rx_queue *pkt_q, unsigned int *cc)
{
	struct bpf_zbuf_header *bzh;

	if (pkt_q->zbuffer == pkt_q->zbuf2 || pkt_q->zbuffer == NULL) {
		bzh = (struct bpf_zbuf_header *)pkt_q->zbuf1;
		if (bzh->bzh_user_gen !=
		    __atomic_load_n(&bzh->bzh_kernel_gen, __ATOMIC_ACQUIRE)) {
			pkt_q->bzh = bzh;
			pkt_q->zbuffer = pkt_q->zbuf1;
			pkt_q->bp = pkt_q->zbuffer + sizeof(*bzh);
			*cc = bzh->bzh_kernel_len;
			return 1;
		}
	} else if (pkt_q->zbuffer == pkt_q->zbuf1) {
		bzh = (struct bpf_zbuf_header *)pkt_q->zbuf2;
		if (bzh->bzh_user_gen !=
		    __atomic_load_n(&bzh->bzh_kernel_gen, __ATOMIC_ACQUIRE)) {
			pkt_q->bzh = bzh;
			pkt_q->zbuffer = pkt_q->zbuf2;
			pkt_q->bp = pkt_q->zbuffer + sizeof(*bzh);
			*cc = bzh->bzh_kernel_len;
			return 1;
		}
	}
	*cc = 0;
	return 0;
}

/*
 * Acknowledge buffer ownership back to kernel
 */
static void
bpf_ack_zbuf(struct pkt_rx_queue *pkt_q)
{
	__atomic_store_n(&pkt_q->bzh->bzh_user_gen,
	    pkt_q->bzh->bzh_kernel_gen, __ATOMIC_RELEASE);
	pkt_q->bzh = NULL;
	pkt_q->bp = NULL;
}

/*
 * Force rotation of zero-copy buffer
 */
static int
bpf_rotate_zbuf(struct pkt_rx_queue *pkt_q, unsigned int *cc)
{
	struct bpf_zbuf bz;

	/* First check if data is already available */
	if (bpf_next_zbuf_shm(pkt_q, cc))
		return 1;

	/* Try forcing a buffer rotation */
	if (ioctl(pkt_q->fd, BIOCROTZBUF, &bz) < 0) {
		PMD_LOG_ERRNO(ERR, "BIOCROTZBUF failed");
		return -1;
	}

	return bpf_next_zbuf_shm(pkt_q, cc);
}
#endif /* HAVE_ZEROCOPY_BPF */

static uint16_t
eth_bpf_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	unsigned i;
	struct bpf_hdr *bhp;
	struct rte_mbuf *mbuf;
	uint8_t *bp, *ep;
	struct pkt_rx_queue *pkt_q = queue;
	uint16_t num_rx = 0;
	unsigned long num_rx_bytes = 0;
	unsigned int caplen, hdrlen;
	size_t packet_bytes;

	if (unlikely(nb_pkts == 0))
		return 0;

	/*
	 * Check if we need to read more data
	 */
	if (pkt_q->cc == 0) {
#ifdef HAVE_ZEROCOPY_BPF
		if (pkt_q->zerocopy) {
			unsigned int cc;

			if (pkt_q->bzh != NULL)
				bpf_ack_zbuf(pkt_q);

			if (bpf_rotate_zbuf(pkt_q, &cc) <= 0)
				return 0;

			pkt_q->cc = cc;
		} else
#endif
		{
			ssize_t read_ret;

			read_ret = read(pkt_q->fd, pkt_q->buffer, pkt_q->bufsize);
			if (read_ret < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return 0;
				PMD_LOG_ERRNO(ERR, "read failed");
				return 0;
			}
			if (read_ret == 0)
				return 0;

			pkt_q->bp = pkt_q->buffer;
			pkt_q->cc = (unsigned int)read_ret;
		}
	}

	bp = pkt_q->bp;
	ep = bp + pkt_q->cc;

	/*
	 * Loop through each packet in the buffer
	 */
	for (i = 0; i < nb_pkts && bp < ep; ) {
		bhp = (struct bpf_hdr *)bp;
		caplen = bhp->bh_caplen;
		hdrlen = bhp->bh_hdrlen;

		/*
		 * Compute the number of bytes for this packet in the buffer
		 */
		packet_bytes = BPF_WORDALIGN(caplen + hdrlen);
		if (bp + packet_bytes > ep)
			break;

		/* Allocate the next mbuf */
		mbuf = rte_pktmbuf_alloc(pkt_q->mb_pool);
		if (unlikely(mbuf == NULL)) {
			pkt_q->rx_nombuf++;
			bp += packet_bytes;
			continue;
		}

		/* Check if packet fits in mbuf */
		if (caplen > rte_pktmbuf_tailroom(mbuf)) {
			rte_pktmbuf_free(mbuf);
			pkt_q->rx_dropped_pkts++;
			bp += packet_bytes;
			continue;
		}

		/* Copy packet data into mbuf */
		rte_pktmbuf_pkt_len(mbuf) = caplen;
		rte_pktmbuf_data_len(mbuf) = caplen;
		memcpy(rte_pktmbuf_mtod(mbuf, void *), bp + hdrlen, caplen);

		mbuf->port = pkt_q->in_port;

		/* Account for the received frame */
		bufs[num_rx] = mbuf;
		num_rx++;
		num_rx_bytes += caplen;
		i++;

		bp += packet_bytes;
	}

	pkt_q->bp = bp;
	pkt_q->cc = (bp < ep) ? (unsigned int)(ep - bp) : 0;
	pkt_q->rx_pkts += num_rx;
	pkt_q->rx_bytes += num_rx_bytes;

	return num_rx;
}

static uint16_t
eth_bpf_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct rte_mbuf *mbuf;
	struct pkt_tx_queue *pkt_q = queue;
	uint16_t num_tx = 0;
	unsigned long num_tx_bytes = 0;
	uint16_t i;
	ssize_t ret;

	if (unlikely(nb_pkts == 0))
		return 0;

	for (i = 0; i < nb_pkts; i++) {
		mbuf = bufs[i];

		/* Drop oversized packets */
		if (mbuf->pkt_len > pkt_q->bufsize) {
			rte_pktmbuf_free(mbuf);
			pkt_q->err_pkts++;
			continue;
		}

		/*
		 * Handle multi-segment mbufs by copying to a contiguous buffer
		 */
		if (mbuf->nb_segs > 1) {
			uint8_t *tx_buf;
			uint8_t *pbuf;
			struct rte_mbuf *tmp_mbuf = mbuf;

			tx_buf = malloc(pkt_q->bufsize);
			if (tx_buf == NULL) {
				rte_pktmbuf_free(mbuf);
				pkt_q->err_pkts++;
				continue;
			}
			pbuf = tx_buf;

			while (tmp_mbuf) {
				uint16_t data_len = rte_pktmbuf_data_len(tmp_mbuf);
				memcpy(pbuf, rte_pktmbuf_mtod(tmp_mbuf, void *), data_len);
				pbuf += data_len;
				tmp_mbuf = tmp_mbuf->next;
			}

			ret = write(pkt_q->fd, tx_buf, mbuf->pkt_len);
			free(tx_buf);
		} else {
			ret = write(pkt_q->fd, rte_pktmbuf_mtod(mbuf, void *),
				    mbuf->pkt_len);
		}

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* Would block, stop transmitting */
				rte_pktmbuf_free(mbuf);
				break;
			}
			PMD_LOG_ERRNO(ERR, "write failed");
			rte_pktmbuf_free(mbuf);
			pkt_q->err_pkts++;
			continue;
		}

		num_tx++;
		num_tx_bytes += mbuf->pkt_len;
		rte_pktmbuf_free(mbuf);
	}

	pkt_q->tx_pkts += num_tx;
	pkt_q->tx_bytes += num_tx_bytes;

	return num_tx;
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;
	uint16_t i;

	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;
	for (i = 0; i < internals->nb_queues; i++) {
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	}
	return 0;
}

static int
eth_dev_stop(struct rte_eth_dev *dev)
{
	unsigned i;
	struct pmd_internals *internals = dev->data->dev_private;

	for (i = 0; i < internals->nb_queues; i++) {
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	}
	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
	return 0;
}

static int
eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	const struct rte_eth_rxmode *rxmode = &dev_conf->rxmode;
	struct pmd_internals *internals = dev->data->dev_private;

	internals->vlan_strip = !!(rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP);
	return 0;
}

static int
eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *internals = dev->data->dev_private;

	dev_info->if_index = internals->if_index;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = RTE_ETHER_MAX_LEN;
	dev_info->max_rx_queues = (uint16_t)internals->nb_queues;
	dev_info->max_tx_queues = (uint16_t)internals->nb_queues;
	dev_info->min_rx_bufsize = 0;
	dev_info->tx_offload_capa = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
	dev_info->rx_offload_capa = RTE_ETH_RX_OFFLOAD_VLAN_STRIP;

	return 0;
}

static int
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats,
	      struct eth_queue_stats *qstats)
{
	unsigned int i;
	unsigned long rx_total = 0, rx_dropped_total = 0, rx_nombuf_total = 0;
	unsigned long tx_total = 0, tx_err_total = 0;
	unsigned long rx_bytes_total = 0, tx_bytes_total = 0;
	const struct pmd_internals *internal = dev->data->dev_private;

	for (i = 0; i < internal->nb_queues; i++) {
		rx_total += internal->rx_queue[i].rx_pkts;
		rx_bytes_total += internal->rx_queue[i].rx_bytes;
		rx_dropped_total += internal->rx_queue[i].rx_dropped_pkts;
		rx_nombuf_total += internal->rx_queue[i].rx_nombuf;

		tx_total += internal->tx_queue[i].tx_pkts;
		tx_err_total += internal->tx_queue[i].err_pkts;
		tx_bytes_total += internal->tx_queue[i].tx_bytes;

		if (qstats != NULL && i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			qstats->q_ipackets[i] = internal->rx_queue[i].rx_pkts;
			qstats->q_ibytes[i] = internal->rx_queue[i].rx_bytes;
			qstats->q_opackets[i] = internal->tx_queue[i].tx_pkts;
			qstats->q_obytes[i] = internal->tx_queue[i].tx_bytes;
			qstats->q_errors[i] = internal->rx_queue[i].rx_nombuf;
		}
	}

	stats->ipackets = rx_total;
	stats->ibytes = rx_bytes_total;
	stats->imissed = rx_dropped_total;
	stats->rx_nombuf = rx_nombuf_total;
	stats->opackets = tx_total;
	stats->oerrors = tx_err_total;
	stats->obytes = tx_bytes_total;
	return 0;
}

static int
eth_stats_reset(struct rte_eth_dev *dev)
{
	unsigned i;
	struct pmd_internals *internal = dev->data->dev_private;

	for (i = 0; i < internal->nb_queues; i++) {
		internal->rx_queue[i].rx_pkts = 0;
		internal->rx_queue[i].rx_bytes = 0;
		internal->rx_queue[i].rx_nombuf = 0;
		internal->rx_queue[i].rx_dropped_pkts = 0;

		internal->tx_queue[i].tx_pkts = 0;
		internal->tx_queue[i].err_pkts = 0;
		internal->tx_queue[i].tx_bytes = 0;
	}

	return 0;
}

static int
eth_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals;
	unsigned int q;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	PMD_LOG(INFO, "Closing BPF ethdev on NUMA socket %u",
		rte_socket_id());

	internals = dev->data->dev_private;
	for (q = 0; q < internals->nb_queues; q++) {
		if (internals->rx_queue[q].fd != -1) {
#ifdef HAVE_ZEROCOPY_BPF
			if (internals->rx_queue[q].zerocopy) {
				if (internals->rx_queue[q].zbuf1 != NULL)
					munmap(internals->rx_queue[q].zbuf1,
					       internals->rx_queue[q].zbufsize);
				if (internals->rx_queue[q].zbuf2 != NULL)
					munmap(internals->rx_queue[q].zbuf2,
					       internals->rx_queue[q].zbufsize);
			} else
#endif
			{
				rte_free(internals->rx_queue[q].buffer);
			}
			close(internals->rx_queue[q].fd);
		}
		internals->rx_queue[q].fd = -1;

		/* TX uses same fd as RX for BPF */
		internals->tx_queue[q].fd = -1;
	}

	rte_free(internals->if_name);
	rte_free(internals->rx_queue);
	rte_free(internals->tx_queue);

	/* mac_addrs must not be freed alone because part of dev_private */
	dev->data->mac_addrs = NULL;
	return 0;
}

static int
eth_link_update(struct rte_eth_dev *dev,
		int wait_to_complete __rte_unused)
{
	const struct pmd_internals *internals = dev->data->dev_private;
	struct rte_eth_link *dev_link = &dev->data->dev_link;
	struct ifreq ifr = { };
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1)
		return 0;

	strlcpy(ifr.ifr_name, internals->if_name, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(sockfd);
		return -errno;
	}
	close(sockfd);

	dev_link->link_status = (ifr.ifr_flags & IFF_RUNNING) ?
		RTE_ETH_LINK_UP : RTE_ETH_LINK_DOWN;
	return 0;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t rx_queue_id,
		   uint16_t nb_rx_desc __rte_unused,
		   unsigned int socket_id __rte_unused,
		   const struct rte_eth_rxconf *rx_conf __rte_unused,
		   struct rte_mempool *mb_pool)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct pkt_rx_queue *pkt_q = &internals->rx_queue[rx_queue_id];
	unsigned int buf_size, data_size;

	pkt_q->mb_pool = mb_pool;

	/* Now get the space available for data in the mbuf */
	buf_size = rte_pktmbuf_data_room_size(pkt_q->mb_pool) -
		RTE_PKTMBUF_HEADROOM;
	data_size = internals->bufsize;

	if (data_size > buf_size) {
		PMD_LOG(ERR,
			"%s: %d bytes will not fit in mbuf (%d bytes)",
			dev->device->name, data_size, buf_size);
		return -ENOMEM;
	}

	dev->data->rx_queues[rx_queue_id] = pkt_q;
	pkt_q->in_port = dev->data->port_id;
	pkt_q->vlan_strip = internals->vlan_strip;

	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t tx_queue_id,
		   uint16_t nb_tx_desc __rte_unused,
		   unsigned int socket_id __rte_unused,
		   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct pmd_internals *internals = dev->data->dev_private;

	dev->data->tx_queues[tx_queue_id] = &internals->tx_queue[tx_queue_id];
	return 0;
}

static int
eth_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct ifreq ifr = { .ifr_mtu = mtu };
	int ret;
	int s;

	if (mtu > internals->bufsize)
		return -EINVAL;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -EINVAL;

	strlcpy(ifr.ifr_name, internals->if_name, IFNAMSIZ);
	ret = ioctl(s, SIOCSIFMTU, &ifr);
	close(s);

	if (ret < 0)
		return -EINVAL;

	return 0;
}

static int
eth_dev_macaddr_set(struct rte_eth_dev *dev, struct rte_ether_addr *addr)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct ifreq ifr = { };
	int sockfd;
	int ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		PMD_LOG_ERRNO(ERR, "socket failed");
		return -EINVAL;
	}

	strlcpy(ifr.ifr_name, internals->if_name, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_LINK;
	memcpy(ifr.ifr_addr.sa_data, addr, sizeof(*addr));
	ret = ioctl(sockfd, SIOCSIFLLADDR, &ifr);
	close(sockfd);

	if (ret < 0) {
		PMD_LOG_ERRNO(ERR, "ioctl(SIOCSIFLLADDR) failed");
		return -EINVAL;
	}

	return 0;
}

static int
eth_dev_change_flags(char *if_name, uint32_t flags, uint32_t mask)
{
	struct ifreq ifr;
	int ret = 0;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -errno;

	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		ret = -errno;
		goto out;
	}
	ifr.ifr_flags &= mask;
	ifr.ifr_flags |= flags;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		ret = -errno;
		goto out;
	}
out:
	close(s);
	return ret;
}

static int
eth_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	return eth_dev_change_flags(internals->if_name, IFF_PROMISC, ~0);
}

static int
eth_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	return eth_dev_change_flags(internals->if_name, 0, ~IFF_PROMISC);
}

static const struct eth_dev_ops ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_close = eth_dev_close,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.mac_addr_set = eth_dev_macaddr_set,
	.mtu_set = eth_dev_mtu_set,
	.promiscuous_enable = eth_dev_promiscuous_enable,
	.promiscuous_disable = eth_dev_promiscuous_disable,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
};

/*
 * Opens a BPF device
 */
static int
open_bpf_device(char *errbuf, size_t errbuf_size)
{
	int fd = -1;
	unsigned int n = 0;
	char device[sizeof "/dev/bpf0000000000"];
	static const char cloning_device[] = "/dev/bpf";

	/*
	 * First, try opening /dev/bpf (cloning device)
	 */
	fd = open(cloning_device, O_RDWR);
	if (fd >= 0)
		return fd;

	if (errno != ENOENT) {
		if (errbuf)
			snprintf(errbuf, errbuf_size,
				 "Could not open %s: %s",
				 cloning_device, strerror(errno));
		return -1;
	}

	/*
	 * No cloning device, try /dev/bpfN
	 */
	do {
		snprintf(device, sizeof(device), "/dev/bpf%u", n++);
		fd = open(device, O_RDWR);
	} while (fd < 0 && errno == EBUSY && n < MAX_BPF_DEVICES);

	if (fd < 0) {
		if (errbuf)
			snprintf(errbuf, errbuf_size,
				 "Could not open BPF device: %s",
				 strerror(errno));
		return -1;
	}

	return fd;
}

/*
 * Bind BPF device to network interface
 */
static int
bind_bpf_device(int fd, const char *if_name, char *errbuf, size_t errbuf_size)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);

	if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
		if (errbuf)
			snprintf(errbuf, errbuf_size,
				 "BIOCSETIF %s failed: %s",
				 if_name, strerror(errno));
		return -1;
	}

	return 0;
}

static int
rte_pmd_init_internals(struct rte_vdev_device *dev,
		       const unsigned nb_queues,
		       unsigned int bufsize,
		       unsigned int zerocopy,
		       const char *if_name,
		       struct pmd_internals **internals,
		       struct rte_eth_dev **eth_dev)
{
	const char *name = rte_vdev_device_name(dev);
	const unsigned int numa_node = dev->device.numa_node;
	struct rte_eth_dev_data *data = NULL;
	struct bpf_version bv;
	struct ifreq ifr;
	struct pkt_rx_queue *rx_queue;
	struct pkt_tx_queue *tx_queue;
	int fd = -1;
	unsigned int q;
	unsigned int v;
	char errbuf[256];
#ifdef HAVE_ZEROCOPY_BPF
	size_t zbufmax;
#endif

	PMD_LOG(INFO,
		"%s: creating BPF-backed ethdev on numa socket %u",
		name, numa_node);

	*internals = rte_zmalloc_socket(name, sizeof(**internals),
					0, numa_node);
	if (*internals == NULL)
		return -1;

	(*internals)->rx_queue = rte_calloc_socket("bpf_rx",
						   nb_queues,
						   sizeof(struct pkt_rx_queue),
						   0, numa_node);
	(*internals)->tx_queue = rte_calloc_socket("bpf_tx",
						   nb_queues,
						   sizeof(struct pkt_tx_queue),
						   0, numa_node);
	if (!(*internals)->rx_queue || !(*internals)->tx_queue)
		goto free_internals;

	for (q = 0; q < nb_queues; q++) {
		(*internals)->rx_queue[q].fd = -1;
		(*internals)->tx_queue[q].fd = -1;
	}

	/* Open first BPF device to get interface info */
	fd = open_bpf_device(errbuf, sizeof(errbuf));
	if (fd < 0) {
		PMD_LOG(ERR, "%s: %s", name, errbuf);
		goto free_internals;
	}

	/* Check BPF version */
	if (ioctl(fd, BIOCVERSION, &bv) < 0) {
		PMD_LOG_ERRNO(ERR, "BIOCVERSION failed");
		goto error;
	}
	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		PMD_LOG(ERR, "Kernel BPF version mismatch");
		goto error;
	}

	/* Get interface index */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
		PMD_LOG_ERRNO(ERR, "%s: BIOCSETIF failed", name);
		goto error;
	}

	/* Get interface index via socket */
	(*internals)->if_index = if_nametoindex(if_name);
	if ((*internals)->if_index == 0) {
		PMD_LOG_ERRNO(ERR, "%s: if_nametoindex failed", name);
		goto error;
	}

	/* Store interface name */
	(*internals)->if_name = rte_malloc_socket(name, strlen(if_name) + 1,
						  0, numa_node);
	if ((*internals)->if_name == NULL)
		goto error;
	strlcpy((*internals)->if_name, if_name, strlen(if_name) + 1);

	/* Get MAC address using getifaddrs() */
	{
		struct ifaddrs *ifap, *ifa;
		struct sockaddr_dl *sdl;

		if (getifaddrs(&ifap) == 0) {
			for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr == NULL)
					continue;
				if (ifa->ifa_addr->sa_family != AF_LINK)
					continue;
				if (strcmp(ifa->ifa_name, if_name) != 0)
					continue;

				sdl = (struct sockaddr_dl *)ifa->ifa_addr;
				if (sdl->sdl_alen == RTE_ETHER_ADDR_LEN) {
					memcpy(&(*internals)->eth_addr,
					       LLADDR(sdl),
					       RTE_ETHER_ADDR_LEN);
				}
				break;
			}
			freeifaddrs(ifap);
		}
	}

	close(fd);
	fd = -1;

	/* Set buffer size */
	(*internals)->bufsize = bufsize;
#ifdef HAVE_ZEROCOPY_BPF
	(*internals)->zerocopy = zerocopy;
#else
	if (zerocopy) {
		PMD_LOG(WARNING, "Zero-copy BPF not supported on this platform");
	}
#endif

	/* Open BPF device for each queue */
	for (q = 0; q < nb_queues; q++) {
		fd = open_bpf_device(errbuf, sizeof(errbuf));
		if (fd < 0) {
			PMD_LOG(ERR, "%s: %s", name, errbuf);
			goto error;
		}

		/* Set buffer size before binding */
		v = bufsize;
		if (ioctl(fd, BIOCSBLEN, &v) < 0) {
			PMD_LOG_ERRNO(ERR, "%s: BIOCSBLEN failed", name);
			goto error;
		}

		/* Bind to interface */
		if (bind_bpf_device(fd, if_name, errbuf, sizeof(errbuf)) < 0) {
			PMD_LOG(ERR, "%s: %s", name, errbuf);
			goto error;
		}

		/* Set immediate mode - return packets immediately */
		v = 1;
		if (ioctl(fd, BIOCIMMEDIATE, &v) < 0) {
			PMD_LOG_ERRNO(ERR, "%s: BIOCIMMEDIATE failed", name);
			goto error;
		}

		/* Enable header complete mode - don't overwrite source MAC */
		v = 1;
		if (ioctl(fd, BIOCSHDRCMPLT, &v) < 0) {
			PMD_LOG_ERRNO(ERR, "%s: BIOCSHDRCMPLT failed", name);
			goto error;
		}

		/* Set to see sent packets as well */
		v = BPF_D_INOUT;
		if (ioctl(fd, BIOCSDIRECTION, &v) < 0) {
			/* Not fatal, may not be supported */
			PMD_LOG(DEBUG, "%s: BIOCSDIRECTION failed", name);
		}

		/* Set non-blocking mode */
		if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
			PMD_LOG_ERRNO(ERR, "%s: fcntl(O_NONBLOCK) failed", name);
			goto error;
		}

		rx_queue = &(*internals)->rx_queue[q];
		tx_queue = &(*internals)->tx_queue[q];

		rx_queue->fd = fd;
		tx_queue->fd = fd;

#ifdef HAVE_ZEROCOPY_BPF
		if (zerocopy) {
			u_int bufmode = BPF_BUFMODE_ZBUF;

			if (ioctl(fd, BIOCSETBUFMODE, &bufmode) < 0) {
				PMD_LOG(WARNING,
					"%s: BIOCSETBUFMODE failed, falling back to buffered mode",
					name);
				zerocopy = 0;
				(*internals)->zerocopy = 0;
			}
		}

		if (zerocopy) {
			struct bpf_zbuf bz;

			/* Get max zero-copy buffer size */
			if (ioctl(fd, BIOCGETZMAX, &zbufmax) < 0) {
				PMD_LOG_ERRNO(ERR, "%s: BIOCGETZMAX failed", name);
				goto error;
			}

			/* Round buffer size to page boundary */
			rx_queue->zbufsize = (bufsize + getpagesize() - 1) &
					     ~(getpagesize() - 1);
			if (rx_queue->zbufsize > zbufmax)
				rx_queue->zbufsize = zbufmax;

			/* Allocate zero-copy buffers */
			rx_queue->zbuf1 = mmap(NULL, rx_queue->zbufsize,
					       PROT_READ | PROT_WRITE,
					       MAP_ANON, -1, 0);
			rx_queue->zbuf2 = mmap(NULL, rx_queue->zbufsize,
					       PROT_READ | PROT_WRITE,
					       MAP_ANON, -1, 0);
			if (rx_queue->zbuf1 == MAP_FAILED ||
			    rx_queue->zbuf2 == MAP_FAILED) {
				PMD_LOG_ERRNO(ERR, "%s: mmap failed", name);
				goto error;
			}

			/* Initialize buffer headers */
			memset(rx_queue->zbuf1, 0, sizeof(struct bpf_zbuf_header));
			memset(rx_queue->zbuf2, 0, sizeof(struct bpf_zbuf_header));

			/* Register buffers with BPF */
			memset(&bz, 0, sizeof(bz));
			bz.bz_bufa = rx_queue->zbuf1;
			bz.bz_bufb = rx_queue->zbuf2;
			bz.bz_buflen = rx_queue->zbufsize;
			if (ioctl(fd, BIOCSETZBUF, &bz) < 0) {
				PMD_LOG_ERRNO(ERR, "%s: BIOCSETZBUF failed", name);
				goto error;
			}

			rx_queue->zerocopy = 1;
			rx_queue->zbuffer = NULL;
			rx_queue->bzh = NULL;
			rx_queue->bufsize = rx_queue->zbufsize -
					    sizeof(struct bpf_zbuf_header);
		} else
#endif
		{
			/* Allocate receive buffer */
			rx_queue->buffer = rte_zmalloc_socket(name, bufsize,
							      0, numa_node);
			if (rx_queue->buffer == NULL) {
				PMD_LOG(ERR, "%s: buffer allocation failed", name);
				goto error;
			}
			rx_queue->bufsize = bufsize;
#ifdef HAVE_ZEROCOPY_BPF
			rx_queue->zerocopy = 0;
#endif
		}

		rx_queue->bp = NULL;
		rx_queue->cc = 0;
		tx_queue->bufsize = bufsize;
		fd = -1;
	}

	/* Reserve an ethdev entry */
	*eth_dev = rte_eth_vdev_allocate(dev, 0);
	if (*eth_dev == NULL)
		goto error;

	/*
	 * Now put it all together
	 */
	(*internals)->nb_queues = nb_queues;

	data = (*eth_dev)->data;
	data->dev_private = *internals;
	data->nb_rx_queues = (uint16_t)nb_queues;
	data->nb_tx_queues = (uint16_t)nb_queues;
	data->dev_link = pmd_link;
	data->mac_addrs = &(*internals)->eth_addr;
	data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	(*eth_dev)->dev_ops = &ops;

	return 0;

error:
	if (fd >= 0)
		close(fd);
	for (q = 0; q < nb_queues; q++) {
		if ((*internals)->rx_queue[q].fd >= 0) {
#ifdef HAVE_ZEROCOPY_BPF
			if ((*internals)->rx_queue[q].zerocopy) {
				if ((*internals)->rx_queue[q].zbuf1 != MAP_FAILED)
					munmap((*internals)->rx_queue[q].zbuf1,
					       (*internals)->rx_queue[q].zbufsize);
				if ((*internals)->rx_queue[q].zbuf2 != MAP_FAILED)
					munmap((*internals)->rx_queue[q].zbuf2,
					       (*internals)->rx_queue[q].zbufsize);
			} else
#endif
			{
				rte_free((*internals)->rx_queue[q].buffer);
			}
			close((*internals)->rx_queue[q].fd);
		}
	}
free_internals:
	rte_free((*internals)->rx_queue);
	rte_free((*internals)->tx_queue);
	rte_free((*internals)->if_name);
	rte_free(*internals);
	return -1;
}

static int
rte_eth_from_bpf(struct rte_vdev_device *dev,
		 struct rte_kvargs *kvlist)
{
	const char *name = rte_vdev_device_name(dev);
	struct pmd_internals *internals = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	struct rte_kvargs_pair *pair = NULL;
	unsigned k_idx;
	unsigned int bufsize = DFLT_BUF_SIZE;
	unsigned int qpairs = 1;
	unsigned int zerocopy = 0;
	const char *if_name = NULL;

	/* Walk arguments for configurable settings */
	for (k_idx = 0; k_idx < kvlist->count; k_idx++) {
		pair = &kvlist->pairs[k_idx];
		if (strstr(pair->key, ETH_BPF_IFACE_ARG) != NULL) {
			if_name = pair->value;
			continue;
		}
		if (strstr(pair->key, ETH_BPF_NUM_Q_ARG) != NULL) {
			qpairs = atoi(pair->value);
			if (qpairs < 1) {
				PMD_LOG(ERR, "%s: invalid qpairs value", name);
				return -1;
			}
			continue;
		}
		if (strstr(pair->key, ETH_BPF_BUFSIZE_ARG) != NULL) {
			bufsize = atoi(pair->value);
			if (!bufsize) {
				PMD_LOG(ERR, "%s: invalid bufsize value", name);
				return -1;
			}
			continue;
		}
		if (strstr(pair->key, ETH_BPF_ZEROCOPY_ARG) != NULL) {
			zerocopy = atoi(pair->value);
			if (zerocopy > 1) {
				PMD_LOG(ERR, "%s: invalid zerocopy value", name);
				return -1;
			}
			continue;
		}
	}

	if (if_name == NULL) {
		PMD_LOG(ERR, "%s: no interface specified", name);
		return -1;
	}

	PMD_LOG(DEBUG, "%s: BPF parameters:", name);
	PMD_LOG(DEBUG, "%s:\tbuffer size %d", name, bufsize);
	PMD_LOG(DEBUG, "%s:\tqueue pairs %d", name, qpairs);
	PMD_LOG(DEBUG, "%s:\tzerocopy %d", name, zerocopy);

	if (rte_pmd_init_internals(dev, qpairs, bufsize, zerocopy,
				   if_name, &internals, &eth_dev) < 0)
		return -1;

	eth_dev->rx_pkt_burst = eth_bpf_rx;
	eth_dev->tx_pkt_burst = eth_bpf_tx;

	rte_eth_dev_probing_finish(eth_dev);
	return 0;
}

static int
rte_pmd_bpf_probe(struct rte_vdev_device *dev)
{
	int ret = 0;
	struct rte_kvargs *kvlist;
	struct rte_eth_dev *eth_dev;
	const char *name = rte_vdev_device_name(dev);

	PMD_LOG(INFO, "Initializing pmd_bpf for %s", name);

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		eth_dev = rte_eth_dev_attach_secondary(name);
		if (!eth_dev) {
			PMD_LOG(ERR, "Failed to probe %s", name);
			return -1;
		}
		eth_dev->dev_ops = &ops;
		eth_dev->device = &dev->device;
		rte_eth_dev_probing_finish(eth_dev);
		return 0;
	}

	kvlist = rte_kvargs_parse(rte_vdev_device_args(dev), valid_arguments);
	if (kvlist == NULL) {
		ret = -1;
		goto exit;
	}

	if (rte_kvargs_count(kvlist, ETH_BPF_IFACE_ARG) == 1) {
		ret = rte_eth_from_bpf(dev, kvlist);
	} else {
		PMD_LOG(ERR, "Missing required argument: %s", ETH_BPF_IFACE_ARG);
		ret = -1;
	}

	if (dev->device.numa_node == SOCKET_ID_ANY)
		dev->device.numa_node = rte_socket_id();

exit:
	rte_kvargs_free(kvlist);
	return ret;
}

static int
rte_pmd_bpf_remove(struct rte_vdev_device *dev)
{
	struct rte_eth_dev *eth_dev;

	if (dev == NULL)
		return -1;

	/* Find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
	if (eth_dev == NULL)
		return 0; /* port already released */

	eth_dev_close(eth_dev);
	rte_eth_dev_release_port(eth_dev);

	return 0;
}

static struct rte_vdev_driver pmd_bpf_drv = {
	.probe = rte_pmd_bpf_probe,
	.remove = rte_pmd_bpf_remove,
};

RTE_PMD_REGISTER_VDEV(net_bpf, pmd_bpf_drv);
RTE_PMD_REGISTER_ALIAS(net_bpf, eth_bpf);
RTE_PMD_REGISTER_PARAM_STRING(net_bpf,
	"iface=<string> "
	"qpairs=<int> "
	"bufsz=<int> "
	"zerocopy=<0|1>");
