/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_alarm.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <vfio_user/vfio_user_pci.h>

#include "iavf.h"
#include "iavf_rxtx.h"

static int iavf_client_dev_close(struct rte_eth_dev *dev);
static int iavf_client_dev_reset(struct rte_eth_dev *dev);

/* set iavf_client_dev_ops to iavf's by default */
static struct eth_dev_ops iavf_client_eth_dev_ops;

static const char *valid_args[] = {
#define AVF_CLIENT_ARG_PATH           "path"
	AVF_CLIENT_ARG_PATH,
	NULL
};

/* set up vfio_device for iavf_client*/
static int
iavf_client_vfio_user_setup(struct rte_eth_dev *dev, const char *path)
{
	struct iavf_adapter *adapter =
		IAVF_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);
	struct iavf_hw *hw = IAVF_DEV_PRIVATE_TO_HW(adapter);
	struct vfio_device *vfio_dev;
	int max_fds, i;

	vfio_dev = client_vfio_user_setup(path, dev->device->numa_node);
	if (vfio_dev == NULL) {
		printf("Error to create vfio_device for iavf_client\n");
		return -1;
	}
	hw->bus.type = iavf_bus_type_vfio_user;

	/* Use hw_addr to record dev ptr */
	hw->hw_addr = (uint8_t *)vfio_dev;

	hw->back = IAVF_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);

	if (!dev->intr_handle) {
		dev->intr_handle = malloc(sizeof(*dev->intr_handle));
		if (!dev->intr_handle) {
			PMD_INIT_LOG(ERR, "fail to allocate intr_handle");
			return -1;
		}
		memset(dev->intr_handle, 0, sizeof(*dev->intr_handle));
	}

	max_fds = RTE_MIN(RTE_MAX_RXTX_INTR_VEC_ID, adapter->vf.num_queue_pairs);

	/* FD for control has been enabled */
	dev->intr_handle->fd = -1;
	dev->intr_handle->type = RTE_INTR_HANDLE_VDEV;
	dev->intr_handle->max_intr = max_fds + 1;
	dev->intr_handle->nb_efd = max_fds;
	for (i = 0; i < max_fds; ++i)
		dev->intr_handle->efds[i] = vfio_dev->irqfds[i];
	dev->intr_handle->efd_counter_size = 0;

	return 0;
}


static inline void
avf_client_init_eth_ops(void)
{
	iavf_client_eth_dev_ops = iavf_eth_dev_ops;
	/* keep other unchanged */
	iavf_client_eth_dev_ops.dev_close  = iavf_client_dev_close,
	iavf_client_eth_dev_ops.dev_reset  = iavf_client_dev_reset,
	iavf_client_eth_dev_ops.dev_supported_ptypes_get   = NULL;
	iavf_client_eth_dev_ops.reta_update                = NULL;
	iavf_client_eth_dev_ops.reta_query                 = NULL;
	iavf_client_eth_dev_ops.rss_hash_update            = NULL;
	iavf_client_eth_dev_ops.rss_hash_conf_get          = NULL;
	iavf_client_eth_dev_ops.rx_queue_intr_enable       = NULL;
	iavf_client_eth_dev_ops.rx_queue_intr_disable      = NULL;
}

#define IAVF_CLIENT_ALARM_INTERVAL 50000 /* us */
static void
iavf_client_dev_alarm_handler(void *param)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;

	iavf_handle_virtchnl_msg(dev);

	rte_eal_alarm_set(IAVF_CLIENT_ALARM_INTERVAL,
			  iavf_client_dev_alarm_handler, dev);
}

/* init ethdev for the avf client device*/
static int
iavf_client_eth_init(struct rte_eth_dev *eth_dev)
{
	struct iavf_adapter *adapter =
		IAVF_DEV_PRIVATE_TO_ADAPTER(eth_dev->data->dev_private);
	struct iavf_hw *hw = IAVF_DEV_PRIVATE_TO_HW(adapter);

	/* update eth_dev_op by assigning ops func pointer */
	avf_client_init_eth_ops();
	eth_dev->dev_ops = (const struct eth_dev_ops *)(&iavf_client_eth_dev_ops);

	eth_dev->rx_pkt_burst = &iavf_recv_pkts;
	eth_dev->tx_pkt_burst = &iavf_xmit_pkts;
	eth_dev->tx_pkt_prepare = &iavf_prep_pkts;

	hw->back = IAVF_DEV_PRIVATE_TO_ADAPTER(eth_dev->data->dev_private);
	adapter->eth_dev = eth_dev;
	adapter->stopped = 1;

	if (iavf_init_vf(eth_dev) != 0) {
		PMD_INIT_LOG(ERR, "Init vf failed");
		return -1;
	}

	/* copy mac addr */
	eth_dev->data->mac_addrs = rte_zmalloc(
			"iavf_client_mac",
			RTE_ETHER_ADDR_LEN * IAVF_NUM_MACADDR_MAX, 0);
	if (!eth_dev->data->mac_addrs) {
		PMD_INIT_LOG(ERR, "Failed to allocate %d bytes needed to"
			     " store MAC addresses",
			     RTE_ETHER_ADDR_LEN * IAVF_NUM_MACADDR_MAX);
		return -ENOMEM;
	}
	/* If the MAC address is not configured by host,
	 * generate a random one.
	 */
	if (!rte_is_valid_assigned_ether_addr(
			(struct rte_ether_addr *)hw->mac.addr))
		rte_eth_random_addr(hw->mac.addr);
	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac.addr,
			&eth_dev->data->mac_addrs[0]);

	rte_eal_alarm_set(IAVF_CLIENT_ALARM_INTERVAL,
			  iavf_client_dev_alarm_handler, eth_dev);
	return 0;
}

static int
iavf_client_dev_reset(struct rte_eth_dev *dev)
{
	struct iavf_hw *hw = IAVF_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	int ret;

	rte_eal_alarm_cancel(iavf_client_dev_alarm_handler, dev);

	iavf_shutdown_adminq(hw);
	ret = iavf_init_vf(dev);

	/* send reset msg to PF */
	iavf_vf_reset(hw);
	rte_eal_alarm_set(IAVF_CLIENT_ALARM_INTERVAL,
			  iavf_client_dev_alarm_handler, dev);

	return ret;
}

static int
iavf_client_dev_close(struct rte_eth_dev *dev)
{
	struct iavf_adapter *adapter =
		IAVF_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);
	struct iavf_hw *hw = IAVF_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct rte_intr_handle *intr_handle = dev->intr_handle;

	if (!adapter->stopped) {
		iavf_stop_queues(dev);

		if (intr_handle) {
			/* Disable the interrupt for Rx */
			rte_intr_efd_disable(intr_handle);
			/* Rx interrupt vector mapping free */
			if (intr_handle->intr_vec) {
				rte_free(intr_handle->intr_vec);
				intr_handle->intr_vec = NULL;
			}
		}
		/* Remove all mac addrs */
		iavf_add_del_all_mac_addr(adapter, false);
		adapter->stopped = 1;
	}
	iavf_shutdown_adminq(hw);
	iavf_disable_irq0(hw);
	rte_eal_alarm_cancel(iavf_client_dev_alarm_handler, dev);

	return 0;
}

static int
iavf_client_get_string_arg(const char *key __rte_unused,
	       const char *value, void *extra_args)
{
	if (!value || !extra_args)
		return -EINVAL;

	*(char **)extra_args = strdup(value);

	if (!*(char **)extra_args)
		return -ENOMEM;

	return 0;
}

static int
avf_client_pmd_probe(struct rte_vdev_device *vdev)
{
	struct rte_kvargs *kvlist = NULL;
	struct rte_eth_dev *eth_dev;
	struct iavf_adapter *adapter;
	char *path = NULL;
	int ret;

	kvlist = rte_kvargs_parse(rte_vdev_device_args(vdev), valid_args);
	if (!kvlist) {
		PMD_INIT_LOG(ERR, "error when parsing param");
		return -EINVAL;
	}

	if (rte_kvargs_count(kvlist, AVF_CLIENT_ARG_PATH) == 1) {
		if (rte_kvargs_process(kvlist, AVF_CLIENT_ARG_PATH,
				       &iavf_client_get_string_arg, &path) < 0) {
			PMD_INIT_LOG(ERR, "error to parse %s",
				     AVF_CLIENT_ARG_PATH);
			return -EINVAL;
		}
	} else {
		PMD_INIT_LOG(ERR, "arg %s is mandatory for virtio_user",
			     AVF_CLIENT_ARG_PATH);
		return -EINVAL;
	}

	eth_dev = rte_eth_vdev_allocate(vdev, sizeof(*adapter));

	ret = iavf_client_vfio_user_setup(eth_dev, path);
	if (ret) {
		goto err;
	}

	ret = iavf_client_eth_init(eth_dev);
	if (ret) {
		goto err;
	}

	rte_eth_dev_probing_finish(eth_dev);
	rte_kvargs_free(kvlist);

	return 0;
err:
	rte_eth_dev_release_port(eth_dev);
	rte_kvargs_free(kvlist);
	return ret;
}


static int
avf_client_pmd_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *eth_dev = NULL;

	if (vdev == NULL)
		return -1;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (eth_dev == NULL)
		return 0;

	iavf_client_dev_close(eth_dev);
	rte_eth_dev_release_port(eth_dev);
	return 0;
}

static struct rte_vdev_driver iavf_client_driver = {
	.probe = avf_client_pmd_probe,
	.remove = avf_client_pmd_remove,
};

RTE_PMD_REGISTER_VDEV(net_iavf_client, iavf_client_driver);
RTE_PMD_REGISTER_ALIAS(net_iavf_client, iavf_client);
RTE_PMD_REGISTER_PARAM_STRING(net_iavf_client,
	"path=<path>");
