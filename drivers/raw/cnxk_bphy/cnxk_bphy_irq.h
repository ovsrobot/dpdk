/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _CNXK_BPHY_IRQ_
#define _CNXK_BPHY_IRQ_

#include <rte_bus_pci.h>
#include <rte_dev.h>

#include <roc_api.h>

struct bphy_mem {
	struct rte_mem_resource res0;
	struct rte_mem_resource res2;
};

struct bphy_device {
	struct roc_bphy_irq_chip *irq_chip;
	struct bphy_mem mem;
};

#endif /* _CNXK_BPHY_IRQ_ */
