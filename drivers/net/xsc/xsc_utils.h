/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_UTILS_H_
#define _XSC_UTILS_H_

#include <infiniband/verbs.h>

#include <ethdev_pci.h>

struct ibv_device *xsc_get_ibv_device(const struct rte_pci_addr *addr);
int xsc_get_ifname_by_pci_addr(struct rte_pci_addr *addr, char *ifname);
int xsc_get_ifindex_by_ifname(const char *ifname, int *ifindex);
int xsc_get_ifindex_by_pci_addr(struct rte_pci_addr *addr, int *ifindex);

#endif /* _XSC_UTILS_H_ */
