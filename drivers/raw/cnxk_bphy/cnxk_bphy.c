/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell International Ltd.
 */
#include <rte_bus_pci.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_pci.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>

#include <roc_api.h>
#include <roc_bphy_irq.h>

#include "cnxk_bphy_irq.h"
#include "rte_pmd_bphy.h"

static const struct rte_pci_id pci_bphy_map[] = {
	{RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_CNXK_BPHY)},
	{
		.vendor_id = 0,
	},
};

struct bphy_test {
	int irq_num;
	cnxk_bphy_intr_handler_t handler;
	void *data;
	int cpu;
	bool handled_intr;
	int handled_data;
	int test_data;
};

static struct bphy_test *test;

static void
bphy_test_handler_fn(int irq_num, void *isr_data)
{
	test[irq_num].handled_intr = true;
	test[irq_num].handled_data = *((int *)isr_data);
}

int
rte_pmd_bphy_intr_init(uint16_t dev_id)
{
	return cnxk_bphy_intr_init(dev_id);
}

void
rte_pmd_bphy_intr_fini(uint16_t dev_id)
{
	return cnxk_bphy_intr_fini(dev_id);
}

struct cnxk_bphy_mem *
rte_pmd_bphy_intr_mem_get(uint16_t dev_id)
{
	return cnxk_bphy_mem_get(dev_id);
}

int
rte_pmd_bphy_intr_register(uint16_t dev_id, int irq_num,
			    cnxk_bphy_intr_handler_t handler, void *data,
			    int cpu)
{
	return cnxk_bphy_intr_register(dev_id, irq_num, handler, data, cpu);
}

void
rte_pmd_bphy_intr_unregister(uint16_t dev_id, int irq_num)
{
	cnxk_bphy_intr_unregister(dev_id, irq_num);
}

static int
bphy_rawdev_selftest(uint16_t dev_id)
{
	unsigned int i;
	uint64_t max_irq;
	int ret = 0;

	ret = rte_pmd_bphy_intr_init(dev_id);
	if (ret) {
		plt_err("intr init failed");
		return ret;
	}

	max_irq = cnxk_bphy_irq_max_get(dev_id);

	test = rte_zmalloc("BPHY", max_irq * sizeof(*test), 0);
	if (test == NULL) {
		plt_err("intr alloc failed");
		goto err_alloc;
	}

	for (i = 0; i < max_irq; i++) {
		test[i].test_data = i;
		test[i].irq_num = i;
		test[i].handler = bphy_test_handler_fn;
		test[i].data = &test[i].test_data;
	}

	for (i = 0; i < max_irq; i++) {
		ret = rte_pmd_bphy_intr_register(dev_id, test[i].irq_num,
						  test[i].handler, test[i].data,
						  0);
		if (ret == -ENOTSUP) {
			/* In the test we iterate over all irq numbers
			 * so if some of them are not supported by given
			 * platform we treat respective results as valid
			 * ones. This way they have no impact on overall
			 * test results.
			 */
			test[i].handled_intr = true;
			test[i].handled_data = test[i].test_data;
			ret = 0;
			continue;
		}

		if (ret) {
			plt_err("intr register failed at irq %d", i);
			goto err_register;
		}
	}

	for (i = 0; i < max_irq; i++)
		roc_bphy_intr_handler(i);

	for (i = 0; i < max_irq; i++) {
		if (!test[i].handled_intr) {
			plt_err("intr %u not handled", i);
			ret = -1;
			break;
		}
		if (test[i].handled_data != test[i].test_data) {
			plt_err("intr %u has wrong handler", i);
			ret = -1;
			break;
		}
	}

err_register:
	/*
	 * In case of registration failure the loop goes over all
	 * interrupts which is safe due to internal guards in
	 * rte_pmd_bphy_intr_unregister().
	 */
	for (i = 0; i < max_irq; i++)
		rte_pmd_bphy_intr_unregister(dev_id, i);

	rte_free(test);
err_alloc:
	rte_pmd_bphy_intr_fini(dev_id);

	return ret;
}

static const struct rte_rawdev_ops bphy_rawdev_ops = {
	.dev_selftest = bphy_rawdev_selftest,
};

static void
bphy_rawdev_get_name(char *name, struct rte_pci_device *pci_dev)
{
	snprintf(name, RTE_RAWDEV_NAME_MAX_LEN, "BPHY:%x:%02x.%x",
		 pci_dev->addr.bus, pci_dev->addr.devid,
		 pci_dev->addr.function);
}

static int
bphy_rawdev_probe(struct rte_pci_driver *pci_drv,
		  struct rte_pci_device *pci_dev)
{
	struct bphy_device *bphy_dev = NULL;
	char name[RTE_RAWDEV_NAME_MAX_LEN];
	struct rte_rawdev *bphy_rawdev;
	int ret;

	RTE_SET_USED(pci_drv);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	if (!pci_dev->mem_resource[0].addr) {
		plt_err("BARs have invalid values: BAR0 %p\n BAR2 %p",
			pci_dev->mem_resource[0].addr,
			pci_dev->mem_resource[2].addr);
		return -ENODEV;
	}

	ret = roc_plt_init();
	if (ret)
		return ret;

	bphy_rawdev_get_name(name, pci_dev);
	bphy_rawdev = rte_rawdev_pmd_allocate(name, sizeof(*bphy_dev),
					      rte_socket_id());
	if (bphy_rawdev == NULL) {
		plt_err("Failed to allocate rawdev");
		return -ENOMEM;
	}

	bphy_rawdev->dev_ops = &bphy_rawdev_ops;
	bphy_rawdev->device = &pci_dev->device;
	bphy_rawdev->driver_name = pci_dev->driver->driver.name;

	bphy_dev = (struct bphy_device *)bphy_rawdev->dev_private;
	bphy_dev->mem.res0 = pci_dev->mem_resource[0];
	bphy_dev->mem.res2 = pci_dev->mem_resource[2];

	return 0;
}

static int
bphy_rawdev_remove(struct rte_pci_device *pci_dev)
{
	char name[RTE_RAWDEV_NAME_MAX_LEN];
	struct rte_rawdev *rawdev;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	if (pci_dev == NULL) {
		plt_err("invalid pci_dev");
		return -EINVAL;
	}

	rawdev = rte_rawdev_pmd_get_named_dev(name);
	if (rawdev == NULL) {
		plt_err("invalid device name (%s)", name);
		return -EINVAL;
	}

	bphy_rawdev_get_name(name, pci_dev);

	return rte_rawdev_pmd_release(rawdev);
}

static struct rte_pci_driver cnxk_bphy_rawdev_pmd = {
	.id_table = pci_bphy_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_NEED_IOVA_AS_VA,
	.probe = bphy_rawdev_probe,
	.remove = bphy_rawdev_remove,
};

RTE_PMD_REGISTER_PCI(bphy_rawdev_pci_driver, cnxk_bphy_rawdev_pmd);
RTE_PMD_REGISTER_PCI_TABLE(bphy_rawdev_pci_driver, pci_bphy_map);
RTE_PMD_REGISTER_KMOD_DEP(bphy_rawdev_pci_driver, "vfio-pci");
