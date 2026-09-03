/* SPDX-License-Identifier: BSD-3-Clause
 *   Copyright 2016,2021 NXP
 */

#ifndef BUS_FSLMC_PRIVATE_H
#define BUS_FSLMC_PRIVATE_H

#include <bus_driver.h>

#include <bus_fslmc_driver.h>

extern struct rte_bus rte_fslmc_bus;

/* MC/SoC version and capability info, shared by the bus and VFIO code. */
extern struct rte_fslmc_bus_info fslmc_bus_info;

#endif /* BUS_FSLMC_PRIVATE_H */
