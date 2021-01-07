/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <sys/eventfd.h>

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

#define AVF_CLIENT_ARG_PATH           "path"
#define AVF_CLIENT_ARG_INTR           "intr"

static int iavf_client_dev_close(struct rte_eth_dev *dev);
static int iavf_client_dev_reset(struct rte_eth_dev *dev);

/* set iavf_client_dev_ops to iavf's by default */
static struct eth_dev_ops iavf_client_eth_dev_ops;

static const char *valid_args[] = {
	AVF_CLIENT_ARG_PATH,
	AVF_CLIENT_ARG_INTR,
	NULL
};

static void
iavf_client_event_handler(void *param)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct iavf_hw *hw = IAVF_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	eventfd_t buf;

	eventfd_read(dev->intr_handle->fd, &buf);

	iavf_disable_irq0(hw);

	iavf_handle_virtchnl_msg(dev);

	iavf_enable_irq0(hw);
}

/* set up vfio_device for iavf_client*/
static int
iavf_client_vfio_user_setup(struct rte_eth_dev *dev, const char *path)
{
	struct iavf_adapter *adapter =
		IAVF_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);
	struct iavf_hw *hw = IAVF_DEV_PRIVATE_TO_HW(adapter);
	struct vfio_device *vfio_dev;

	vfio_dev = client_vfio_user_setup(path, dev->device->numa_node);
	if (vfio_dev == NULL) {
		PMD_INIT_LOG(ERR, "Error to create vfio_device for iavf_client\n");
		return -1;
	}
	hw->bus.type = iavf_bus_type_vfio_user;

	/* Use hw_addr to record dev ptr */
	hw->hw_addr = (uint8_t *)vfio_dev;

	hw->back = IAVF_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);

	if (!vfio_dev->nb_irqs && adapter->intr_mode) {
		PMD_INIT_LOG(ERR, "No irq support on device");
		return -1;
	}

	if (!dev->intr_handle) {
		dev->intr_handle = rte_zmalloc_socket("iavf_client_intr",
				sizeof(*dev->intr_handle),
				0, dev->device->numa_node);
		if (!dev->intr_handle) {
			PMD_INIT_LOG(ERR, "fail to allocate intr_handle");
			return -1;
		}

	}

	dev->intr_handle->fd = vfio_dev->irqfds[0];
	dev->intr_handle->type = RTE_INTR_HANDLE_VDEV;
	dev->intr_handle->max_intr = 1;

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

	/* set default ptype table */
	adapter->ptype_tbl = iavf_get_default_ptype_table();

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

	if (adapter->intr_mode) {
		/* register callback func to eal lib */
		rte_intr_callback_register(eth_dev->intr_handle,
					   iavf_client_event_handler,
					   (void *)eth_dev);
		iavf_enable_irq0(hw);
	} else {
		rte_eal_alarm_set(IAVF_CLIENT_ALARM_INTERVAL,
				  iavf_client_dev_alarm_handler, eth_dev);
	}
	return 0;
}

static int
iavf_client_dev_reset(struct rte_eth_dev *dev)
{
	struct iavf_adapter *adapter =
		IAVF_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);
	struct iavf_hw *hw = IAVF_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct rte_intr_handle *intr_handle = dev->intr_handle;
	int ret;

	if (adapter->intr_mode) {
		iavf_disable_irq0(hw);
		/* unregister callback func from eal lib */
		rte_intr_callback_unregister(intr_handle,
					     iavf_client_event_handler, dev);
	} else {
		rte_eal_alarm_cancel(iavf_client_dev_alarm_handler, dev);
	}

	iavf_shutdown_adminq(hw);
	ret = iavf_init_vf(dev);

	/* send reset msg to PF */
	iavf_vf_reset(hw);
	if (adapter->intr_mode) {
		/* register callback func to eal lib */
		rte_intr_callback_register(dev->intr_handle,
					   iavf_client_event_handler,
					   (void *)dev);
		iavf_enable_irq0(hw);
	} else {
		rte_eal_alarm_set(IAVF_CLIENT_ALARM_INTERVAL,
				  iavf_client_dev_alarm_handler, dev);
	}

	return ret;
}

static int
iavf_client_dev_close(struct rte_eth_dev *dev)
{
	struct iavf_adapter *adapter =
		IAVF_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);
	struct iavf_hw *hw = IAVF_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	if (adapter->intr_mode) {
		iavf_disable_irq0(hw);
		/* unregister callback func from eal lib */
		rte_intr_callback_unregister(dev->intr_handle,
					     iavf_client_event_handler, dev);
	} else {
		rte_eal_alarm_cancel(iavf_client_dev_alarm_handler, dev);
	}

	if (!adapter->stopped) {
		iavf_stop_queues(dev);

		if (dev->intr_handle) {
			rte_free(dev->intr_handle);
			dev->intr_handle = NULL;
		}

		/* Remove all mac addrs */
		iavf_add_del_all_mac_addr(adapter, false);
		adapter->stopped = 1;
	}

	iavf_shutdown_adminq(hw);
	client_vfio_user_release((struct vfio_device *)hw->hw_addr);

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
iavf_client_intr_check(__rte_unused const char *key,
			const char *value, void *opaque)
{
	int *intr = (int *)opaque;
	int ret = 0;

	if (!strcmp(value, "1"))
		*intr  = 1;
	else if (!strcmp(value, "0"))
		*intr = 0;
	else
		ret = -1;

	return ret;
}

static int
iavf_client_pmd_probe(struct rte_vdev_device *vdev)
{
	struct rte_kvargs *kvlist = NULL;
	struct rte_eth_dev *eth_dev;
	struct iavf_adapter *adapter;
	char *path = NULL;
	int intr_mode = 0;
	int ret;

	kvlist = rte_kvargs_parse(rte_vdev_device_args(vdev), valid_args);
	if (!kvlist) {
		PMD_INIT_LOG(ERR, "error when parsing param");
		return -EINVAL;
	}

	if (rte_kvargs_count(kvlist, AVF_CLIENT_ARG_PATH) == 1) {
		if (rte_kvargs_process(kvlist, AVF_CLIENT_ARG_PATH,
					&iavf_client_get_string_arg,
					&path) < 0) {
			PMD_INIT_LOG(ERR, "error to parse %s",
				     AVF_CLIENT_ARG_PATH);
			ret = -EINVAL;
			goto free_kvlist;
		}
	} else {
		PMD_INIT_LOG(ERR, "arg %s is mandatory for iavf_client",
			     AVF_CLIENT_ARG_PATH);
		ret = -EINVAL;
		goto free_kvlist;
	}

	if (rte_kvargs_count(kvlist, AVF_CLIENT_ARG_INTR) == 1) {
		if (rte_kvargs_process(kvlist, AVF_CLIENT_ARG_INTR,
					iavf_client_intr_check,
					&intr_mode) < 0) {
			PMD_INIT_LOG(ERR, "arg %s must be 1 or 0",
				     AVF_CLIENT_ARG_INTR);
			ret = -EINVAL;
			goto free_kvlist;
		}
	}

	eth_dev = rte_eth_vdev_allocate(vdev, sizeof(*adapter));

	ret = iavf_client_vfio_user_setup(eth_dev, path);
	if (ret)
		goto err;

	adapter = IAVF_DEV_PRIVATE_TO_ADAPTER(eth_dev->data->dev_private);
	adapter->intr_mode = intr_mode;

	ret = iavf_client_eth_init(eth_dev);
	if (ret)
		goto err;

	rte_eth_dev_probing_finish(eth_dev);

	rte_kvargs_free(kvlist);

	return 0;
err:
	rte_eth_dev_release_port(eth_dev);
free_kvlist:
	rte_kvargs_free(kvlist);
	return ret;
}


static int
iavf_client_pmd_remove(struct rte_vdev_device *vdev)
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
	.probe = iavf_client_pmd_probe,
	.remove = iavf_client_pmd_remove,
};

RTE_PMD_REGISTER_VDEV(net_iavf_client, iavf_client_driver);
RTE_PMD_REGISTER_ALIAS(net_iavf_client, iavf_client);
RTE_PMD_REGISTER_PARAM_STRING(net_iavf_client,
	"path=<path>"
	"intr=[0|1]");
