/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>

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

#include "rtap.h"

#define RTAP_DEFAULT_IFNAME	"rtap%d"

#define RTAP_IFACE_ARG		"iface"
#define RTAP_PERSIST_ARG	"persist"

static const char * const valid_arguments[] = {
	RTAP_IFACE_ARG,
	RTAP_PERSIST_ARG,
	NULL
};

static int
rtap_dev_close(struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;

	PMD_LOG(INFO, "Closing %s", pmd->ifname);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		/* mac_addrs must not be freed alone because part of dev_private */
		dev->data->mac_addrs = NULL;

		if (pmd->keep_fd != -1) {
			PMD_LOG(DEBUG, "Closing keep_fd %d", pmd->keep_fd);
			close(pmd->keep_fd);
			pmd->keep_fd = -1;
		}
	}

	free(dev->process_private);
	dev->process_private = NULL;

	return 0;
}

static const struct eth_dev_ops rtap_ops = {
	.dev_close		= rtap_dev_close,
};

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

	RTE_SET_USED(persist); /* used in later patches */

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
