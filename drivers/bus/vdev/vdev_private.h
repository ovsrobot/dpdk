/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Gaëtan Rivet
 */

#ifndef _VDEV_PRIVATE_H_
#define _VDEV_PRIVATE_H_

#include <rte_os_shim.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rte_device *
rte_vdev_find_device(const struct rte_device *start,
		     rte_dev_cmp_t cmp,
		     const struct rte_bus_address *data);

void *
rte_vdev_dev_iterate(const void *start,
		     const char *str,
		     const struct rte_dev_iterator *it);

#ifdef __cplusplus
}
#endif

#endif /* _VDEV_PRIVATE_H_ */
