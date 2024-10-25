/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */


#include <errno.h>
#include <stdint.h>

#include "zsda_device.h"

/* per-process array of device data */
struct zsda_device_info zsda_devs[RTE_PMD_ZSDA_MAX_PCI_DEVICES];
static int zsda_nb_pci_devices;

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_zsda_map[] = {
	{
		RTE_PCI_DEVICE(0x1cf2, 0x8050),
	},
	{
		RTE_PCI_DEVICE(0x1cf2, 0x8051),
	},
	{.device_id = 0},
};

static struct zsda_pci_device *
zsda_pci_get_named_dev(const char *name)
{
	unsigned int i;

	if (name == NULL) {
		ZSDA_LOG(ERR, E_NULL);
		return NULL;
	}

	for (i = 0; i < RTE_PMD_ZSDA_MAX_PCI_DEVICES; i++) {
		if (zsda_devs[i].mz &&
		    (strcmp(((struct zsda_pci_device *)zsda_devs[i].mz->addr)
				    ->name,
			    name) == 0))
			return (struct zsda_pci_device *)zsda_devs[i].mz->addr;
	}

	return NULL;
}

static uint8_t
zsda_pci_find_free_device_index(void)
{
	uint32_t dev_id;

	for (dev_id = 0; dev_id < RTE_PMD_ZSDA_MAX_PCI_DEVICES; dev_id++)
		if (zsda_devs[dev_id].mz == NULL)
			break;

	return dev_id & (ZSDA_MAX_DEV - 1);
}

struct zsda_pci_device *
zsda_get_zsda_dev_from_pci_dev(const struct rte_pci_device *pci_dev)
{
	char name[ZSDA_DEV_NAME_MAX_LEN];

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	return zsda_pci_get_named_dev(name);
}

struct zsda_pci_device *
zsda_pci_device_allocate(struct rte_pci_device *pci_dev)
{
	struct zsda_pci_device *zsda_pci_dev;
	uint8_t zsda_dev_id;
	char name[ZSDA_DEV_NAME_MAX_LEN];
	unsigned int socket_id = rte_socket_id();

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));
	snprintf(name + strlen(name), (ZSDA_DEV_NAME_MAX_LEN - strlen(name)),
		 "_zsda");
	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		const struct rte_memzone *mz = rte_memzone_lookup(name);

		if (mz == NULL) {
			ZSDA_LOG(ERR, "Secondary can't find %s mz", name);
			return NULL;
		}
		zsda_pci_dev = mz->addr;
		zsda_devs[zsda_pci_dev->zsda_dev_id].mz = mz;
		zsda_devs[zsda_pci_dev->zsda_dev_id].pci_dev = pci_dev;
		zsda_nb_pci_devices++;
		return zsda_pci_dev;
	}

	if (zsda_pci_get_named_dev(name) != NULL) {
		ZSDA_LOG(ERR, E_CONFIG);
		return NULL;
	}

	zsda_dev_id = zsda_pci_find_free_device_index();

	if (zsda_dev_id == (RTE_PMD_ZSDA_MAX_PCI_DEVICES - 1)) {
		ZSDA_LOG(ERR, "Reached maximum number of ZSDA devices");
		return NULL;
	}

	zsda_devs[zsda_dev_id].mz =
		rte_memzone_reserve(name, sizeof(struct zsda_pci_device),
				    (int)(socket_id & 0xfff), 0);

	if (zsda_devs[zsda_dev_id].mz == NULL) {
		ZSDA_LOG(ERR, E_MALLOC);
		return NULL;
	}

	zsda_pci_dev = zsda_devs[zsda_dev_id].mz->addr;
	memset(zsda_pci_dev, 0, sizeof(*zsda_pci_dev));
	strlcpy(zsda_pci_dev->name, name, ZSDA_DEV_NAME_MAX_LEN);
	zsda_pci_dev->zsda_dev_id = zsda_dev_id;
	zsda_pci_dev->pci_dev = pci_dev;
	zsda_devs[zsda_dev_id].pci_dev = pci_dev;

	zsda_nb_pci_devices++;

	return zsda_pci_dev;
}

static int
zsda_pci_device_release(const struct rte_pci_device *pci_dev)
{
	struct zsda_pci_device *zsda_pci_dev;
	struct zsda_device_info *inst;
	char name[ZSDA_DEV_NAME_MAX_LEN];

	if (pci_dev == NULL)
		return -EINVAL;

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	snprintf(name + strlen(name),
		 ZSDA_DEV_NAME_MAX_LEN - (strlen(name) - 1), "_zsda");
	zsda_pci_dev = zsda_pci_get_named_dev(name);
	if (zsda_pci_dev != NULL) {
		inst = &zsda_devs[zsda_pci_dev->zsda_dev_id];

		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			if ((zsda_pci_dev->sym_dev != NULL) ||
			    (zsda_pci_dev->comp_dev != NULL)) {
				ZSDA_LOG(DEBUG, "ZSDA device %s is busy", name);
				return -EBUSY;
			}
			rte_memzone_free(inst->mz);
		}
		memset(inst, 0, sizeof(struct zsda_device_info));
		zsda_nb_pci_devices--;
	}
	return 0;
}

static int
zsda_pci_dev_destroy(struct zsda_pci_device *zsda_pci_dev,
		     const struct rte_pci_device *pci_dev)
{
	zsda_sym_dev_destroy(zsda_pci_dev);
	zsda_comp_dev_destroy(zsda_pci_dev);

	return zsda_pci_device_release(pci_dev);
}

static int
zsda_unmask_flr(const struct zsda_pci_device *zsda_pci_dev)
{
	struct zsda_admin_req_qcfg req = {0};
	struct zsda_admin_resp_qcfg resp = {0};

	int ret = 0;
	struct rte_pci_device *pci_dev =
		zsda_devs[zsda_pci_dev->zsda_dev_id].pci_dev;

	zsda_admin_msg_init(pci_dev);

	req.msg_type = ZSDA_FLR_SET_FUNCTION;

	ret = zsda_send_admin_msg(pci_dev, &req, sizeof(req));
	if (ret) {
		ZSDA_LOG(ERR, "Failed! Send msg");
		return ret;
	}

	ret = zsda_recv_admin_msg(pci_dev, &resp, sizeof(resp));
	if (ret) {
		ZSDA_LOG(ERR, "Failed! Receive msg");
		return ret;
	}

	return ZSDA_SUCCESS;
}

static int
zsda_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	       struct rte_pci_device *pci_dev)
{
	int ret = 0;
	struct zsda_pci_device *zsda_pci_dev;

	zsda_pci_dev = zsda_pci_device_allocate(pci_dev);
	if (zsda_pci_dev == NULL) {
		ZSDA_LOG(ERR, E_NULL);
		return -ENODEV;
	}

	ret = zsda_queue_init(zsda_pci_dev);
	if (ret) {
		ZSDA_LOG(ERR, "Failed! queue init.");
		return ret;
	}

	ret = zsda_unmask_flr(zsda_pci_dev);
	if (ret) {
		ZSDA_LOG(ERR, "Failed! flr close.");
		return ret;
	}

	ret = zsda_sym_dev_create(zsda_pci_dev);
	ret |= zsda_comp_dev_create(zsda_pci_dev);
	if (ret) {
		ZSDA_LOG(ERR, "Failed! dev create.");
		zsda_pci_dev_destroy(zsda_pci_dev, pci_dev);
		return ret;
	}

	return ret;
}

static int
zsda_pci_remove(struct rte_pci_device *pci_dev)
{
	struct zsda_pci_device *zsda_pci_dev;

	if (pci_dev == NULL)
		return -EINVAL;

	zsda_pci_dev = zsda_get_zsda_dev_from_pci_dev(pci_dev);
	if (zsda_pci_dev == NULL)
		return 0;

	if (zsda_queue_remove(zsda_pci_dev))
		ZSDA_LOG(ERR, "Failed! q remove");

	return zsda_pci_dev_destroy(zsda_pci_dev, pci_dev);
}

static struct rte_pci_driver rte_zsda_pmd = {
	.id_table = pci_id_zsda_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = zsda_pci_probe,
	.remove = zsda_pci_remove };

RTE_PMD_REGISTER_PCI(ZSDA_PCI_NAME, rte_zsda_pmd);
RTE_PMD_REGISTER_PCI_TABLE(ZSDA_PCI_NAME, pci_id_zsda_map);
RTE_PMD_REGISTER_KMOD_DEP(ZSDA_PCI_NAME,
			  "* igb_uio | uio_pci_generic | vfio-pci");
