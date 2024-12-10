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
	struct ifreq ifr = { .ifr_mtu = mtu };
	int ret;

	strlcpy(ifr.ifr_name, pmd->ifname, IFNAMSIZ);

	ret = ioctl(pmd->ctl_sock, SIOCSIFMTU, &ifr);
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
	struct ifreq ifr = { };
	int ret;

	strlcpy(ifr.ifr_name, pmd->ifname, IFNAMSIZ);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(ifr.ifr_hwaddr.sa_data, addr, sizeof(*addr));

	ret = ioctl(pmd->ctl_sock, SIOCSIFHWADDR, &ifr);
	if (ret < 0) {
		PMD_LOG(ERR, "ioctl(SIOCSIFHWADDR) failed: %s", strerror(errno));
		ret = -errno;
	}

	return ret;
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

static int
ioring_probe(struct rte_vdev_device *vdev)
{
	const char *name = rte_vdev_device_name(vdev);
	const char *params = rte_vdev_device_args(vdev);
	struct rte_kvargs *kvlist = NULL;
	struct rte_eth_dev *eth_dev = NULL;
	char tap_name[IFNAMSIZ] = IORING_DEFAULT_IFNAME;
	uint8_t persist = 0;
	int ret;

	PMD_LOG(INFO, "Initializing %s", name);

	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return -1; /* TODO */

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

	eth_dev = rte_eth_vdev_allocate(vdev, sizeof(struct pmd_internals));
	if (eth_dev == NULL) {
		PMD_LOG(ERR, "%s Unable to allocate device struct", tap_name);
		goto error;
	}

	if (ioring_create(eth_dev, tap_name, persist) < 0)
		goto error;

	rte_eth_dev_probing_finish(eth_dev);
	return 0;

error:
	if (eth_dev != NULL)
		rte_eth_dev_release_port(eth_dev);
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
