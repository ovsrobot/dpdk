/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <rte_kvargs.h>
#include <ethdev_vdev.h>
#include <rte_bus_vdev.h>
#include <rte_dev.h>
#include <rte_ether.h>
#include "enet_pmd_logs.h"
#include "enet_ethdev.h"

#define ENETFEC_NAME_PMD        net_enetfec
#define ENET_VDEV_GEM_ID_ARG    "intf"
#define ENET_CDEV_INVALID_FD    -1

int enetfec_logtype_pmd;

static int
enetfec_eth_init(struct rte_eth_dev *dev)
{
	rte_eth_dev_probing_finish(dev);
	return 0;
}

static int
pmd_enetfec_probe(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *dev = NULL;
	struct enetfec_private *fep;
	const char *name;
	int rc = -1;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;
	ENET_PMD_LOG(INFO, "Initializing pmd_fec for %s", name);

	dev = rte_eth_vdev_allocate(vdev, sizeof(*fep));
	if (dev == NULL)
		return -ENOMEM;

	/* setup board info structure */
	fep = dev->data->dev_private;
	fep->dev = dev;
	rc = enetfec_eth_init(dev);
	if (rc)
		goto failed_init;
	return 0;
failed_init:
	ENET_PMD_ERR("Failed to init");
	return rc;
}

static int
pmd_enetfec_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *eth_dev = NULL;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (!eth_dev)
		return -ENODEV;

	rte_eth_dev_release_port(eth_dev);

	ENET_PMD_INFO("Closing sw device\n");
	return 0;
}

static
struct rte_vdev_driver pmd_enetfec_drv = {
	.probe = pmd_enetfec_probe,
	.remove = pmd_enetfec_remove,
};

RTE_PMD_REGISTER_VDEV(ENETFEC_NAME_PMD, pmd_enetfec_drv);
RTE_PMD_REGISTER_PARAM_STRING(ENETFEC_NAME_PMD, ENET_VDEV_GEM_ID_ARG "=<int>");

RTE_INIT(enetfec_pmd_init_log)
{
	enetfec_logtype_pmd = rte_log_register("pmd.net.enetfec");
	if (enetfec_logtype_pmd >= 0)
		rte_log_set_level(enetfec_logtype_pmd, RTE_LOG_NOTICE);
}
