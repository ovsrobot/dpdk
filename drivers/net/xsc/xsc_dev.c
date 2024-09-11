/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_malloc.h>
#include <rte_kvargs.h>

#include "xsc_log.h"
#include "xsc_defs.h"
#include "xsc_dev.h"
#include "xsc_utils.h"
#include "xsc_ctrl.h"

#define XSC_DEV_DEF_FLOW_MODE	XSC_FLOW_MODE_NULL
#define XSC_DEV_CTRL_FILE_FMT	"/dev/yunsilicon/port_ctrl_" PCI_PRI_FMT

static int xsc_hwinfo_init(struct xsc_dev *dev)
{
	struct {
		struct xsc_ioctl_data_tl tl;
		struct xsc_ioctl_get_hwinfo hwinfo;
	} data;
	struct xsc_ioctl_get_hwinfo *info = &data.hwinfo;
	int data_len;
	int ret;

	PMD_INIT_FUNC_TRACE();

	data_len = sizeof(data);
	data.tl.opmod = XSC_IOCTL_OP_GET_LOCAL;
	ret = xsc_ioctl(dev, XSC_IOCTL_DRV_GET, XSC_IOCTL_GET_HW_INFO, &data, data_len,
			&data, data_len);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get hardware info");
		return ret;
	}

	dev->hwinfo.valid = 1;
	dev->hwinfo.pcie_no = info->pcie_no;
	dev->hwinfo.func_id = info->func_id;
	dev->hwinfo.pcie_host = info->pcie_host;
	dev->hwinfo.mac_phy_port = info->mac_phy_port;
	dev->hwinfo.funcid_to_logic_port_off = info->funcid_to_logic_port_off;
	dev->hwinfo.lag_id = info->lag_id;
	dev->hwinfo.raw_qp_id_base = info->raw_qp_id_base;
	dev->hwinfo.raw_rss_qp_id_base = info->raw_rss_qp_id_base;
	dev->hwinfo.pf0_vf_funcid_base = info->pf0_vf_funcid_base;
	dev->hwinfo.pf0_vf_funcid_top = info->pf0_vf_funcid_top;
	dev->hwinfo.pf1_vf_funcid_base = info->pf1_vf_funcid_base;
	dev->hwinfo.pf1_vf_funcid_top = info->pf1_vf_funcid_top;
	dev->hwinfo.pcie0_pf_funcid_base = info->pcie0_pf_funcid_base;
	dev->hwinfo.pcie0_pf_funcid_top = info->pcie0_pf_funcid_top;
	dev->hwinfo.pcie1_pf_funcid_base = info->pcie1_pf_funcid_base;
	dev->hwinfo.pcie1_pf_funcid_top = info->pcie1_pf_funcid_top;
	dev->hwinfo.lag_port_start = info->lag_port_start;
	dev->hwinfo.raw_tpe_qp_num = info->raw_tpe_qp_num;
	dev->hwinfo.send_seg_num = info->send_seg_num;
	dev->hwinfo.recv_seg_num = info->recv_seg_num;
	dev->hwinfo.on_chip_tbl_vld = info->on_chip_tbl_vld;
	dev->hwinfo.dma_rw_tbl_vld = info->dma_rw_tbl_vld;
	dev->hwinfo.pct_compress_vld = info->pct_compress_vld;
	dev->hwinfo.chip_version = info->chip_version;
	dev->hwinfo.hca_core_clock = info->hca_core_clock;
	dev->hwinfo.mac_bit = info->mac_bit;
	dev->hwinfo.esw_mode = info->esw_mode;

	return 0;
}

static
void xsc_dev_args_parse(struct xsc_dev *dev, struct rte_devargs *devargs)
{
	struct rte_kvargs *kvlist;
	struct xsc_devargs *xdevargs = &dev->devargs;
	const char *tmp;

	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL)
		return;

	tmp = rte_kvargs_get(kvlist, XSC_PPH_MODE_ARG);
	if (tmp != NULL)
		xdevargs->pph_mode = atoi(tmp);
	else
		xdevargs->pph_mode = XSC_PPH_NONE;
	tmp = rte_kvargs_get(kvlist, XSC_NIC_MODE_ARG);
	if (tmp != NULL)
		xdevargs->nic_mode = atoi(tmp);
	else
		xdevargs->nic_mode = XSC_NIC_MODE_LEGACY;
	tmp = rte_kvargs_get(kvlist, XSC_FLOW_MODE_ARG);
	if (tmp != NULL)
		xdevargs->flow_mode = atoi(tmp);
	else
		xdevargs->flow_mode = XSC_DEV_DEF_FLOW_MODE;

	rte_kvargs_free(kvlist);
}

static int
xsc_dev_open(struct xsc_dev *dev, struct rte_pci_device *pci_dev)
{
	struct ibv_device *ib_dev;
	char ctrl_file[PATH_MAX];
	struct rte_pci_addr *pci_addr = &pci_dev->addr;
	int ret;

	ib_dev = xsc_get_ibv_device(&pci_dev->addr);
	if (ib_dev == NULL) {
		PMD_DRV_LOG(ERR, "Could not get ibv device");
		return -ENODEV;
	}

	dev->ibv_ctx = ibv_open_device(ib_dev);
	if (dev->ibv_ctx == NULL) {
		PMD_DRV_LOG(ERR, "Could not open ibv device: %s", ib_dev->name);
		return -ENODEV;
	}

	dev->ibv_pd = ibv_alloc_pd(dev->ibv_ctx);
	if (dev->ibv_pd == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create pd:%s", ib_dev->name);
		ret = -EINVAL;
		goto alloc_pd_fail;
	}

	strcpy(dev->ibv_name, ib_dev->name);

	snprintf(ctrl_file, PATH_MAX, XSC_DEV_CTRL_FILE_FMT,
		 pci_addr->domain, pci_addr->bus, pci_addr->devid, pci_addr->function);

	ret = open(ctrl_file, O_RDWR);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "Failed to open file: (%s) ", ctrl_file);
		goto open_ctrl_file_fail;
	}
	dev->ctrl_fd = ret;

	dev->bar_len = pci_dev->mem_resource[0].len;
	dev->bar_addr = mmap(NULL, dev->bar_len, PROT_READ | PROT_WRITE,
			     MAP_SHARED, dev->ctrl_fd, 0);
	if (dev->bar_addr == MAP_FAILED) {
		PMD_DRV_LOG(ERR, "Failed to mmap file: (%s) ", ctrl_file);
		ret = -EINVAL;
		goto mmap_fail;
	}

	return 0;

mmap_fail:
	close(dev->ctrl_fd);
open_ctrl_file_fail:
	ibv_dealloc_pd(dev->ibv_pd);
alloc_pd_fail:
	ibv_close_device(dev->ibv_ctx);

	return ret;
}

static void
xsc_dev_close(struct xsc_dev *dev)
{
	munmap(dev->bar_addr, dev->bar_len);
	close(dev->ctrl_fd);
	ibv_close_device(dev->ibv_ctx);
}

int
xsc_dev_init(struct rte_pci_device *pci_dev, struct xsc_dev **dev)
{
	struct xsc_dev *d;
	int ret;

	PMD_INIT_FUNC_TRACE();

	d = rte_zmalloc(NULL, sizeof(*d), RTE_CACHE_LINE_SIZE);
	if (d == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc memory for xsc_dev");
		return -ENOMEM;
	}

	xsc_dev_args_parse(d, pci_dev->device.devargs);

	ret = xsc_dev_open(d, pci_dev);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to open xsc device");
		goto dev_open_fail;
	}

	ret = xsc_hwinfo_init(d);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to initialize hardware info");
		goto hwinfo_init_fail;
		return ret;
	}

	d->pci_dev = pci_dev;
	*dev = d;

	return 0;

hwinfo_init_fail:
	xsc_dev_close(d);
dev_open_fail:
	rte_free(d);
	return ret;
}

void
xsc_dev_uninit(struct xsc_dev *dev)
{
	PMD_INIT_FUNC_TRACE();

	xsc_dev_close(dev);
	rte_free(dev);
}
