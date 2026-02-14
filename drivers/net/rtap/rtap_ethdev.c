/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_kvargs.h>
#include <rte_log.h>
#include <bus_vdev_driver.h>
#include <ethdev_driver.h>
#include <ethdev_vdev.h>

#include "rtap.h"

#define RTAP_DEFAULT_IFNAME	"rtap%d"

#define RTAP_IFACE_ARG		"iface"
#define RTAP_PERSIST_ARG	"persist"

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
rtap_dev_start(struct rte_eth_dev *dev)
{
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

	if (ioctl(pmd->keep_fd, TUNSETOFFLOAD, 0) != 0) {
		int ret = -errno;

		PMD_LOG(ERR, "ioctl(TUNSETOFFLOAD) failed: %s", strerror(errno));
		return ret;
	}

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
	}

	free(dev->process_private);
	dev->process_private = NULL;

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
	.dev_close		= rtap_dev_close,
	.rx_queue_setup		= rtap_rx_queue_setup,
	.rx_queue_release	= rtap_rx_queue_release,
	.tx_queue_setup		= rtap_tx_queue_setup,
	.tx_queue_release	= rtap_tx_queue_release,
};

static int
rtap_create(struct rte_eth_dev *dev, const char *tap_name, uint8_t persist)
{
	struct rte_eth_dev_data *data = dev->data;
	struct rtap_pmd *pmd = data->dev_private;

	pmd->keep_fd = -1;
	pmd->nlsk_fd = -1;

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
