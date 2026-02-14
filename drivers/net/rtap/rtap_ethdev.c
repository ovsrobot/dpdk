/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if_link.h>
#include <linux/virtio_net.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_kvargs.h>
#include <rte_log.h>
#include <rte_stdatomic.h>
#include <bus_vdev_driver.h>
#include <ethdev_driver.h>
#include <ethdev_vdev.h>

#include "rtap.h"

#define RTAP_DEFAULT_IFNAME	"rtap%d"

#define RTAP_TX_OFFLOAD		(RTE_ETH_TX_OFFLOAD_MULTI_SEGS | \
				 RTE_ETH_TX_OFFLOAD_UDP_CKSUM | \
				 RTE_ETH_TX_OFFLOAD_TCP_CKSUM | \
				 RTE_ETH_TX_OFFLOAD_TCP_TSO)

#define RTAP_RX_OFFLOAD		(RTE_ETH_RX_OFFLOAD_UDP_CKSUM | \
				 RTE_ETH_RX_OFFLOAD_TCP_CKSUM | \
				 RTE_ETH_RX_OFFLOAD_TCP_LRO | \
				 RTE_ETH_RX_OFFLOAD_SCATTER)

#define RTAP_MP_KEY		"rtap_mp_send_fds"

#define RTAP_DEFAULT_BURST	64
#define RTAP_NUM_BUFFERS	1024
#define RTAP_MAX_QUEUES		128
#define RTAP_MIN_RX_BUFSIZE	RTE_ETHER_MIN_LEN
#define RTAP_MAX_RX_PKTLEN	RTE_ETHER_MAX_JUMBO_FRAME_LEN

static_assert(RTAP_MAX_QUEUES <= RTE_MP_MAX_FD_NUM, "Max queues exceeds MP fd limit");

#define RTAP_IFACE_ARG		"iface"
#define RTAP_PERSIST_ARG	"persist"

static RTE_ATOMIC(unsigned int) rtap_dev_count;

static const char * const valid_arguments[] = {
	RTAP_IFACE_ARG,
	RTAP_PERSIST_ARG,
	NULL
};

/* Creates a new tap device, name returned in ifr */
static int
rtap_tap_open(const char *name, struct ifreq *ifr, uint8_t persist)
{
	static const char tun_dev[] = "/dev/net/tun";
	int tap_fd;

	tap_fd = open(tun_dev, O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (tap_fd < 0) {
		PMD_LOG_ERRNO(ERR, "Open %s failed", tun_dev);
		return -1;
	}

	int features = 0;
	if (ioctl(tap_fd, TUNGETFEATURES, &features) < 0) {
		PMD_LOG_ERRNO(ERR, "ioctl(TUNGETFEATURES): %s", tun_dev);
		goto error;
	}

	int flags = IFF_TAP | IFF_MULTI_QUEUE | IFF_NO_PI | IFF_VNET_HDR;
	if ((features & flags) != flags) {
		PMD_LOG(ERR, "TUN features %#x missing support for %#x",
			features, flags & ~features);
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
		PMD_LOG_ERRNO(ERR, "ioctl(TUNSETIFF) %s", ifr->ifr_name);
		goto error;
	}

	/* (Optional) keep the device after application exit */
	if (persist && ioctl(tap_fd, TUNSETPERSIST, 1) < 0) {
		PMD_LOG_ERRNO(ERR, "ioctl(TUNSETPERSIST) %s", ifr->ifr_name);
		goto error;
	}

	int hdr_size = sizeof(struct virtio_net_hdr);
	if (ioctl(tap_fd, TUNSETVNETHDRSZ, &hdr_size) < 0) {
		PMD_LOG(ERR, "ioctl(TUNSETVNETHDRSZ) %s", strerror(errno));
		goto error;
	}

	return tap_fd;
error:
	close(tap_fd);
	return -1;
}

static int
rtap_set_link_up(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	return rtap_nl_change_flags(pmd->nlsk_fd, pmd->if_index, IFF_UP, IFF_UP);
}

static int
rtap_set_link_down(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	return rtap_nl_change_flags(pmd->nlsk_fd, pmd->if_index, 0, IFF_UP);
}

static int
rtap_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	return rtap_nl_change_flags(pmd->nlsk_fd, pmd->if_index, IFF_PROMISC, IFF_PROMISC);
}

static int
rtap_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	return rtap_nl_change_flags(pmd->nlsk_fd, pmd->if_index, 0, IFF_PROMISC);
}

static int
rtap_allmulticast_enable(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	return rtap_nl_change_flags(pmd->nlsk_fd, pmd->if_index, IFF_ALLMULTI, IFF_ALLMULTI);
}

static int
rtap_allmulticast_disable(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	return rtap_nl_change_flags(pmd->nlsk_fd, pmd->if_index, 0, IFF_ALLMULTI);
}

int
rtap_link_update(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	struct rte_eth_link link = {
		.link_speed = RTE_ETH_SPEED_NUM_UNKNOWN,
		.link_duplex = RTE_ETH_LINK_FULL_DUPLEX,
		.link_autoneg = RTE_ETH_LINK_FIXED,
		.link_status = RTE_ETH_LINK_DOWN,
	};
	unsigned int flags = 0;

	if (rtap_nl_get_flags(pmd->nlsk_fd, pmd->if_index, &flags) < 0)
		return -1;

	if ((flags & IFF_UP) && (flags & IFF_RUNNING))
		link.link_status = RTE_ETH_LINK_UP;

	rte_eth_linkstatus_set(dev, &link);
	return 0;
}

static int
rtap_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	return rtap_nl_set_mtu(pmd->nlsk_fd, pmd->if_index, mtu);
}

static int
rtap_macaddr_set(struct rte_eth_dev *dev, struct rte_ether_addr *addr)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	return rtap_nl_set_mac(pmd->nlsk_fd, pmd->if_index, addr);
}

static int
rtap_dev_start(struct rte_eth_dev *dev)
{
	int ret;

	ret = rtap_lsc_set(dev, 1);
	if (ret != 0)
		return ret;

	/* Install Rx interrupt vector if requested by application */
	if (dev->data->dev_conf.intr_conf.rxq) {
		ret = rtap_rx_intr_vec_install(dev);
		if (ret != 0) {
			rtap_lsc_set(dev, 0);
			return ret;
		}
	}

	ret = rtap_set_link_up(dev);
	if (ret != 0) {
		rtap_rx_intr_vec_uninstall(dev);
		rtap_lsc_set(dev, 0);
		return ret;
	}

	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;
	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	}

	return 0;
}

static int
rtap_dev_stop(struct rte_eth_dev *dev)
{
	int *fds = dev->process_private;

	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;

	rtap_rx_intr_vec_uninstall(dev);
	rtap_lsc_set(dev, 0);
	rtap_set_link_down(dev);

	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		for (uint16_t i = 0; i < RTE_MAX_QUEUES_PER_PORT; i++) {
			if (fds[i] == -1)
				continue;

			close(fds[i]);
			fds[i] = -1;
		}
	}

	return 0;
}

static int
rtap_dev_configure(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	/* rx/tx must be paired */
	if (dev->data->nb_rx_queues != dev->data->nb_tx_queues) {
		PMD_LOG(ERR, "number of rx %u and tx %u queues must match",
			dev->data->nb_rx_queues, dev->data->nb_tx_queues);
		return -EINVAL;
	}

	/*
	 * LSC and Rx queue interrupts both need dev->intr_handle,
	 * so they cannot be enabled simultaneously.
	 */
	if (dev->data->dev_conf.intr_conf.lsc &&
	    dev->data->dev_conf.intr_conf.rxq) {
		PMD_LOG(ERR, "LSC and Rx queue interrupts are mutually exclusive");
		return -ENOTSUP;
	}

	/*
	 * Set offload flags visible on the kernel network interface.
	 * This controls whether kernel will use checksum offload etc.
	 * Note: kernel transmit is DPDK receive.
	 */
	const struct rte_eth_rxmode *rx_mode = &dev->data->dev_conf.rxmode;
	unsigned int offload = 0;
	if (rx_mode->offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM) {
		offload |= TUN_F_CSUM;

		if (rx_mode->offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO)
			offload |= TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;
	}

	if (ioctl(pmd->keep_fd, TUNSETOFFLOAD, offload) != 0) {
		int ret = -errno;

		PMD_LOG(ERR, "ioctl(TUNSETOFFLOAD) failed: %s", strerror(errno));
		return ret;
	}

	return 0;
}

static int
rtap_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	dev_info->if_index = pmd->if_index;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = RTAP_MAX_RX_PKTLEN;
	dev_info->min_rx_bufsize = RTAP_MIN_RX_BUFSIZE;
	dev_info->max_rx_queues = RTAP_MAX_QUEUES;
	dev_info->max_tx_queues = RTAP_MAX_QUEUES;
	dev_info->rx_queue_offload_capa = RTAP_RX_OFFLOAD;
	dev_info->rx_offload_capa = dev_info->rx_queue_offload_capa;
	dev_info->tx_queue_offload_capa = RTAP_TX_OFFLOAD;
	dev_info->tx_offload_capa = dev_info->tx_queue_offload_capa;

	dev_info->default_rxportconf = (struct rte_eth_dev_portconf) {
		.burst_size = RTAP_DEFAULT_BURST,
		.ring_size = RTAP_NUM_BUFFERS,
		.nb_queues = 1,
	};
	dev_info->default_txportconf = (struct rte_eth_dev_portconf) {
		.burst_size = RTAP_DEFAULT_BURST,
		.ring_size = RTAP_NUM_BUFFERS,
		.nb_queues = 1,
	};
	return 0;
}

static int
rtap_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats,
	       struct eth_queue_stats *qstats)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	struct rtnl_link_stats64 kstats;
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct rtap_rx_queue *rxq = dev->data->rx_queues[i];
		if (rxq == NULL)
			continue;

		stats->ipackets += rxq->rx_packets;
		stats->ibytes += rxq->rx_bytes;
		stats->ierrors += rxq->rx_errors;

		if (qstats != NULL && i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			qstats->q_ipackets[i] = rxq->rx_packets;
			qstats->q_ibytes[i] = rxq->rx_bytes;
			qstats->q_errors[i] = rxq->rx_errors;
		}
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct rtap_tx_queue *txq = dev->data->tx_queues[i];
		if (txq == NULL)
			continue;

		stats->opackets += txq->tx_packets;
		stats->obytes += txq->tx_bytes;
		stats->oerrors += txq->tx_errors;

		if (qstats != NULL && i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			qstats->q_opackets[i] = txq->tx_packets;
			qstats->q_obytes[i] = txq->tx_bytes;
		}
	}

	/* Get kernel rx_dropped counter via netlink */
	if (rtap_nl_get_stats(pmd->if_index, &kstats) == 0 &&
	    kstats.rx_dropped > pmd->rx_drop_base)
		stats->imissed = kstats.rx_dropped - pmd->rx_drop_base;

	return 0;
}

static int
rtap_stats_reset(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	struct rtnl_link_stats64 kstats;
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct rtap_rx_queue *rxq = dev->data->rx_queues[i];
		if (rxq == NULL)
			continue;

		rxq->rx_packets = 0;
		rxq->rx_bytes = 0;
		rxq->rx_errors = 0;
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct rtap_tx_queue *txq = dev->data->tx_queues[i];
		if (txq == NULL)
			continue;

		txq->tx_packets = 0;
		txq->tx_bytes = 0;
		txq->tx_errors = 0;
	}

	/* Capture current rx_dropped as baseline via netlink */
	if (rtap_nl_get_stats(pmd->if_index, &kstats) == 0)
		pmd->rx_drop_base = kstats.rx_dropped;

	return 0;
}

static int
rtap_dev_close(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	int *fds = dev->process_private;

	PMD_LOG(INFO, "Closing ifindex %d", pmd->if_index);

	/* Release all io_uring queues (calls rx/tx_queue_release for each) */
	rte_eth_dev_internal_reset(dev);

	/* Close any remaining queue fds (each process owns its own set) */
	for (uint16_t i = 0; i < RTE_MAX_QUEUES_PER_PORT; i++) {
		if (fds[i] == -1)
			continue;
		PMD_LOG(DEBUG, "Closed queue %u fd %d", i, fds[i]);
		close(fds[i]);
		fds[i] = -1;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		/* mac_addrs must not be freed alone because part of dev_private */
		dev->data->mac_addrs = NULL;

		if (pmd->keep_fd != -1) {
			PMD_LOG(DEBUG, "Closing keep_fd %d", pmd->keep_fd);
			close(pmd->keep_fd);
			pmd->keep_fd = -1;
		}

		if (pmd->nlsk_fd != -1) {
			close(pmd->nlsk_fd);
			pmd->nlsk_fd = -1;
		}

		rte_intr_instance_free(pmd->rx_intr_handle);
		pmd->rx_intr_handle = NULL;

		rte_intr_instance_free(pmd->intr_handle);
		pmd->intr_handle = NULL;
	}

	free(dev->process_private);
	dev->process_private = NULL;

	if (rte_atomic_fetch_sub_explicit(&rtap_dev_count, 1, rte_memory_order_release) == 1)
		rte_mp_action_unregister(RTAP_MP_KEY);
	return 0;
}

/* Setup another fd to TAP device for the queue */
int
rtap_queue_open(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	int *fds = dev->process_private;
	char ifname[IFNAMSIZ];

	if (fds[queue_id] != -1) {
		PMD_LOG(DEBUG, "queue %u already has fd %d", queue_id, fds[queue_id]);
		return 0;	/* already setup */
	}

	/* Convert ifindex to name for TUNSETIFF */
	if (if_indextoname(pmd->if_index, ifname) == NULL) {
		PMD_LOG(ERR, "Could not find interface for ifindex %d", pmd->if_index);
		return -1;
	}

	struct ifreq ifr = { 0 };
	int tap_fd = rtap_tap_open(ifname, &ifr, 0);
	if (tap_fd < 0) {
		PMD_LOG(ERR, "tap_open failed");
		return -1;
	}

	PMD_LOG(DEBUG, "Opened %d for queue %u", tap_fd, queue_id);
	fds[queue_id] = tap_fd;
	return 0;
}

void
rtap_queue_close(struct rte_eth_dev *dev, uint16_t queue_id)
{
	int *fds = dev->process_private;
	int tap_fd = fds[queue_id];

	if (tap_fd == -1)
		return; /* already closed */
	PMD_LOG(DEBUG, "Closed queue %u fd %d", queue_id, tap_fd);
	close(tap_fd);
	fds[queue_id] = -1;
}

static const struct eth_dev_ops rtap_ops = {
	.dev_start		= rtap_dev_start,
	.dev_stop		= rtap_dev_stop,
	.dev_configure		= rtap_dev_configure,
	.dev_infos_get		= rtap_dev_info,
	.dev_close		= rtap_dev_close,
	.link_update		= rtap_link_update,
	.dev_set_link_up	= rtap_set_link_up,
	.dev_set_link_down	= rtap_set_link_down,
	.mac_addr_set		= rtap_macaddr_set,
	.mtu_set		= rtap_mtu_set,
	.promiscuous_enable	= rtap_promiscuous_enable,
	.promiscuous_disable	= rtap_promiscuous_disable,
	.allmulticast_enable	= rtap_allmulticast_enable,
	.allmulticast_disable	= rtap_allmulticast_disable,
	.stats_get		= rtap_stats_get,
	.stats_reset		= rtap_stats_reset,
	.xstats_get		= rtap_xstats_get,
	.xstats_get_names	= rtap_xstats_get_names,
	.xstats_reset		= rtap_xstats_reset,
	.rx_queue_setup		= rtap_rx_queue_setup,
	.rx_queue_release	= rtap_rx_queue_release,
	.tx_queue_setup		= rtap_tx_queue_setup,
	.tx_queue_release	= rtap_tx_queue_release,
	.rx_queue_intr_enable	= rtap_rx_queue_intr_enable,
	.rx_queue_intr_disable	= rtap_rx_queue_intr_disable,
};

static int
rtap_create(struct rte_eth_dev *dev, const char *tap_name, uint8_t persist)
{
	struct rte_eth_dev_data *data = dev->data;
	struct rtap_pmd *pmd = data->dev_private;

	pmd->keep_fd = -1;
	pmd->nlsk_fd = -1;
	pmd->rx_drop_base = 0;

	/* Allocate interrupt instance for link state change events */
	pmd->intr_handle = rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_SHARED);
	if (pmd->intr_handle == NULL) {
		PMD_LOG(ERR, "Failed to allocate intr handle");
		goto error;
	}
	rte_intr_type_set(pmd->intr_handle, RTE_INTR_HANDLE_EXT);
	rte_intr_fd_set(pmd->intr_handle, -1);
	dev->intr_handle = pmd->intr_handle;
	data->dev_flags |= RTE_ETH_DEV_INTR_LSC;

	dev->dev_ops = &rtap_ops;

	/* Get the initial fd used to keep the tap device around */
	struct ifreq ifr = { 0 };
	pmd->keep_fd = rtap_tap_open(tap_name, &ifr, persist);
	if (pmd->keep_fd < 0)
		goto error;

	PMD_LOG(DEBUG, "Created %s keep_fd %d", ifr.ifr_name, pmd->keep_fd);

	/* Use if_index which is stable even if interface is renamed */
	pmd->if_index = if_nametoindex(ifr.ifr_name);
	if (pmd->if_index == 0) {
		PMD_LOG(ERR, "Could not find ifindex for '%s'", ifr.ifr_name);
		goto error;
	}

	/* Open persistent netlink socket for control operations */
	pmd->nlsk_fd = rtap_nl_open(0);
	if (pmd->nlsk_fd < 0)
		goto error;

	/* Read the MAC address assigned by the kernel via netlink */
	if (rtap_nl_get_mac(pmd->nlsk_fd, pmd->if_index, &pmd->eth_addr) < 0) {
		PMD_LOG(ERR, "Unable to get MAC address for ifindex %d", pmd->if_index);
		goto error;
	}
	data->mac_addrs = &pmd->eth_addr;

	/* Detach this instance, not used for traffic */
	ifr.ifr_flags = IFF_DETACH_QUEUE;
	if (ioctl(pmd->keep_fd, TUNSETQUEUE, &ifr) < 0) {
		PMD_LOG_ERRNO(ERR, "Unable to detach keep-alive queue for ifindex %d",
			      pmd->if_index);
		goto error;
	}

	PMD_LOG(DEBUG, "ifindex %d setup", pmd->if_index);

	dev->rx_pkt_burst = rtap_rx_burst;
	dev->tx_pkt_burst = rtap_tx_burst;

	return 0;

error:
	if (pmd->nlsk_fd != -1)
		close(pmd->nlsk_fd);
	if (pmd->keep_fd != -1)
		close(pmd->keep_fd);
	rte_intr_instance_free(pmd->intr_handle);
	pmd->intr_handle = NULL;
	return -1;
}

static int
rtap_parse_iface(const char *key __rte_unused, const char *value, void *extra_args)
{
	char *name = extra_args;

	/* must not be null string */
	if (value == NULL || value[0] == '\0' || strnlen(value, IFNAMSIZ) == IFNAMSIZ)
		return -EINVAL;

	strlcpy(name, value, IFNAMSIZ);
	return 0;
}

/* Secondary process requests rxq fds from primary. */
static int
rtap_request_fds(const char *name, struct rte_eth_dev *dev)
{
	struct rte_mp_msg request = { };

	strlcpy(request.name, RTAP_MP_KEY, sizeof(request.name));
	strlcpy((char *)request.param, name, RTE_MP_MAX_PARAM_LEN);
	request.len_param = strlen(name) + 1;

	/* Send the request and receive the reply */
	PMD_LOG(DEBUG, "Sending multi-process IPC request for %s", name);

	struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
	struct rte_mp_reply replies;
	int ret = rte_mp_request_sync(&request, &replies, &timeout);
	if (ret < 0) {
		PMD_LOG(ERR, "Failed to request fds from primary: %s",
			rte_strerror(rte_errno));
		return -1;
	}

	struct rte_mp_msg *reply = replies.msgs;
	PMD_LOG(DEBUG, "Received multi-process IPC reply for %s", name);

	if (replies.nb_received != 1) {
		PMD_LOG(ERR, "Got %u replies from primary", replies.nb_received);
		free(reply);
		return -EINVAL;
	}

	if (dev->data->nb_rx_queues != reply->num_fds) {
		PMD_LOG(ERR, "Incorrect number of fds received: %d != %d",
			reply->num_fds, dev->data->nb_rx_queues);
		free(reply);
		return -EINVAL;
	}

	int *fds = dev->process_private;
	for (int i = 0; i < reply->num_fds; i++) {
		fds[i] = reply->fds[i];
		PMD_LOG(DEBUG, "Received queue %u fd %d from primary", i, fds[i]);
	}

	free(reply);
	return 0;
}

/* Primary process sends rxq fds to secondary. */
static int
rtap_mp_send_fds(const struct rte_mp_msg *request, const void *peer)
{
	const char *request_name = (const char *)request->param;

	PMD_LOG(DEBUG, "Received multi-process IPC request for %s", request_name);

	/* Find the requested port */
	struct rte_eth_dev *dev = rte_eth_dev_get_by_name(request_name);
	if (dev == NULL) {
		PMD_LOG(ERR, "Failed to get port id for %s", request_name);
		return -1;
	}

	/* Populate the reply with the fds for each queue */
	struct rte_mp_msg reply = { };
	if (dev->data->nb_rx_queues > RTE_MP_MAX_FD_NUM) {
		PMD_LOG(ERR, "Number of rx queues (%d) exceeds max number of fds (%d)",
			   dev->data->nb_rx_queues, RTE_MP_MAX_FD_NUM);
		return -EINVAL;
	}

	int *fds = dev->process_private;
	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		PMD_LOG(DEBUG, "Send queue %u fd %d to secondary", i, fds[i]);
		reply.fds[reply.num_fds++] = fds[i];
	}

	/* Send the reply */
	strlcpy(reply.name, request->name, sizeof(reply.name));
	strlcpy((char *)reply.param, request_name, RTE_MP_MAX_PARAM_LEN);
	reply.len_param = strlen(request_name) + 1;

	PMD_LOG(DEBUG, "Sending multi-process IPC reply for %s", request_name);
	if (rte_mp_reply(&reply, peer) < 0) {
		PMD_LOG(ERR, "Failed to reply to multi-process IPC request");
		return -1;
	}
	return 0;
}

static int
rtap_probe(struct rte_vdev_device *vdev)
{
	const char *name = rte_vdev_device_name(vdev);
	const char *params = rte_vdev_device_args(vdev);
	struct rte_kvargs *kvlist = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	int *fds = NULL;
	char tap_name[IFNAMSIZ] = RTAP_DEFAULT_IFNAME;
	uint8_t persist = 0;
	int ret;

	PMD_LOG(INFO, "Initializing %s", name);

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		eth_dev = rte_eth_dev_attach_secondary(name);
		if (eth_dev == NULL) {
			PMD_LOG(ERR, "Failed to probe %s", name);
			return -1;
		}
		eth_dev->dev_ops = &rtap_ops;
		eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
		eth_dev->device = &vdev->device;

		if (!rte_eal_primary_proc_alive(NULL)) {
			PMD_LOG(ERR, "Primary process is missing");
			goto error;
		}

		fds = calloc(RTE_MAX_QUEUES_PER_PORT, sizeof(int));
		if (fds == NULL) {
			PMD_LOG(ERR, "Failed to alloc memory for process private");
			goto error;
		}
		for (uint16_t i = 0; i < RTE_MAX_QUEUES_PER_PORT; i++)
			fds[i] = -1;

		eth_dev->process_private = fds;

		if (rtap_request_fds(name, eth_dev))
			goto error;

		rte_eth_dev_probing_finish(eth_dev);
		return 0;
	}

	if (params != NULL) {
		kvlist = rte_kvargs_parse(params, valid_arguments);
		if (kvlist == NULL)
			return -1;

		if (rte_kvargs_count(kvlist, RTAP_IFACE_ARG) == 1) {
			ret = rte_kvargs_process_opt(kvlist, RTAP_IFACE_ARG,
						     &rtap_parse_iface, tap_name);
			if (ret < 0)
				goto error;
		}

		if (rte_kvargs_count(kvlist, RTAP_PERSIST_ARG) == 1)
			persist = 1;
	}

	/* Per-queue tap fd's (for primary process) */
	fds = calloc(RTE_MAX_QUEUES_PER_PORT, sizeof(int));
	if (fds == NULL) {
		PMD_LOG(ERR, "Unable to allocate fd array");
		goto error;
	}
	for (unsigned int i = 0; i < RTE_MAX_QUEUES_PER_PORT; i++)
		fds[i] = -1;

	eth_dev = rte_eth_vdev_allocate(vdev, sizeof(struct rtap_pmd));
	if (eth_dev == NULL) {
		PMD_LOG(ERR, "%s Unable to allocate device struct", tap_name);
		goto error;
	}

	eth_dev->dev_ops = &rtap_ops;
	eth_dev->process_private = fds;
	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	if (rtap_create(eth_dev, tap_name, persist) < 0)
		goto error;

	/* register the MP server on the first device */
	if (rte_atomic_fetch_add_explicit(&rtap_dev_count, 1, rte_memory_order_acquire) == 0 &&
	    rte_mp_action_register(RTAP_MP_KEY, rtap_mp_send_fds) < 0) {
		rte_atomic_store_explicit(&rtap_dev_count, 0, rte_memory_order_relaxed);
		PMD_LOG(ERR, "Failed to register multi-process callback: %s",
			rte_strerror(rte_errno));
		goto error;
	}

	rte_eth_dev_probing_finish(eth_dev);
	rte_kvargs_free(kvlist);
	return 0;

error:
	if (eth_dev != NULL) {
		eth_dev->process_private = NULL;
		rte_eth_dev_release_port(eth_dev);
	}
	free(fds);
	rte_kvargs_free(kvlist);
	return -1;
}

static int
rtap_remove(struct rte_vdev_device *dev)
{
	struct rte_eth_dev *eth_dev;

	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
	if (eth_dev == NULL)
		return 0;

	rtap_dev_close(eth_dev);
	rte_eth_dev_release_port(eth_dev);
	return 0;
}

static struct rte_vdev_driver pmd_rtap_drv = {
	.probe = rtap_probe,
	.remove = rtap_remove,
};

RTE_PMD_REGISTER_VDEV(net_rtap, pmd_rtap_drv);
RTE_PMD_REGISTER_ALIAS(net_rtap, eth_rtap);
RTE_PMD_REGISTER_PARAM_STRING(net_rtap,
	RTAP_IFACE_ARG "=<string> "
	RTAP_PERSIST_ARG);
RTE_LOG_REGISTER_DEFAULT(rtap_logtype, NOTICE);
