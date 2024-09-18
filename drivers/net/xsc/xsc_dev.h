/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_DEV_H_
#define _XSC_DEV_H_

#include <infiniband/verbs.h>

#define XSC_PPH_MODE_ARG "pph_mode"
#define XSC_NIC_MODE_ARG "nic_mode"
#define XSC_FLOW_MODE_ARG "flow_mode"

struct xsc_devargs {
	int nic_mode;
	int flow_mode;
	int pph_mode;
};

struct xsc_dev {
	struct rte_pci_device *pci_dev;
	struct xsc_devargs devargs;
	struct ibv_context *ibv_ctx;
	struct ibv_pd *ibv_pd;
	char ibv_name[IBV_SYSFS_NAME_MAX];
	void *bar_addr;
	uint64_t bar_len;
	int ctrl_fd;
};

int xsc_dev_init(struct rte_pci_device *pci_dev, struct xsc_dev **dev);
void xsc_dev_uninit(struct xsc_dev *dev);

#endif /* _XSC_DEV_H_ */
