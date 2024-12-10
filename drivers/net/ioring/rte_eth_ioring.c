/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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

#define IORING_DEFAULT_IFNAME	"enio%d"
#define IORING_MP_KEY		"ioring_mp_send_fds"

RTE_LOG_REGISTER_DEFAULT(ioring_logtype, NOTICE);
#define RTE_LOGTYPE_IORING ioring_logtype
#define PMD_LOG(level, ...) RTE_LOG_LINE_PREFIX(level, IORING, "%s(): ", __func__, __VA_ARGS__)

#define IORING_IFACE_ARG	"iface"
#define IORING_PERSIST_ARG	"persist"

static const char * const valid_arguments[] = {
	IORING_IFACE_ARG,
	IORING_PERSIST_ARG,
	NULL
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

	return 0;
}

static int
eth_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	PMD_LOG(INFO, "Closing %s", pmd->ifname);

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
