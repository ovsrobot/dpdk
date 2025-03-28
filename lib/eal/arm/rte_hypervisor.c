/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <eal_symbol_exports.h>
#include "rte_hypervisor.h"

RTE_EXPORT_SYMBOL(rte_hypervisor_get)
enum rte_hypervisor
rte_hypervisor_get(void)
{
	return RTE_HYPERVISOR_UNKNOWN;
}
