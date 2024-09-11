/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#include <ethdev_pci.h>
#include <rte_kvargs.h>

#include "xsc_log.h"
#include "xsc_defs.h"
#include "xsc_dev.h"
#include "xsc_ethdev.h"
#include "xsc_utils.h"
#include "xsc_flow.h"
#include "xsc_ctrl.h"


static int
xsc_flow_exec(struct xsc_dev *dev, void *cmd, int len, int table, int opmod)
{
	struct xsc_ioctl_data_tl *tl;
	struct xsc_ioctl_mbox_in *in;
	struct xsc_ioctl_mbox_out *out;
	int in_len;
	int out_len;
	int data_len;
	int cmd_len;
	int ret;

	data_len = sizeof(struct xsc_ioctl_data_tl) + len;
	in_len = sizeof(struct xsc_ioctl_mbox_in) + data_len;
	out_len = sizeof(struct xsc_ioctl_mbox_out) + data_len;
	cmd_len = RTE_MAX(in_len, out_len);
	in = rte_zmalloc(NULL, cmd_len, RTE_CACHE_LINE_SIZE);
	if (in == NULL) {
		rte_errno = ENOMEM;
		PMD_DRV_LOG(ERR, "alloc flow ioctl cmd memory failed\n");
		return -rte_errno;
	}

	in->hdr.opcode = rte_cpu_to_be_16(XSC_CMD_OP_IOCTL_FLOW);
	in->len = rte_cpu_to_be_16(data_len);

	tl = (struct xsc_ioctl_data_tl *)in->data;
	tl->length = len;
	tl->table = table;
	tl->opmod = opmod;
	if (cmd && len)
		rte_memcpy(tl + 1, cmd, len);

	out = (struct xsc_ioctl_mbox_out *)in;
	ret = xsc_mailbox_exec(dev, in, in_len, out, out_len);

	rte_free(in);
	return ret;
}

int
xsc_create_pct(struct rte_eth_dev *dev, uint16_t logical_in_port,
	       uint16_t dst_info, uint32_t priority)
{
	struct xsc_flow_pct_v4_add {
		struct xsc_pct_v4_key key;
		struct xsc_pct_v4_key mask;
		struct xsc_pct_action action;
		uint32_t priority;
	} add;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	memset(&add, 0, sizeof(add));


	add.key.logical_in_port = logical_in_port & 0x07FF;
	add.mask.logical_in_port = 0x07FF;
	add.action.dst_info = dst_info;
	add.priority = priority;
	return xsc_flow_exec(priv->xdev, &add, sizeof(add),
			XSC_FLOW_TBL_PCT_V4, XSC_IOCTL_OP_ADD);
}

int
xsc_destroy_pct(struct rte_eth_dev *dev, uint16_t logical_in_port, uint32_t priority)
{
	struct xsc_flow_pct_v4_add {
		struct xsc_pct_v4_key key;
		struct xsc_pct_v4_key mask;
		uint32_t priority;
	} del;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	memset(&del, 0, sizeof(del));

	del.key.logical_in_port = logical_in_port & 0x07FF;
	del.mask.logical_in_port = 0x07FF;
	del.priority = priority;
	return xsc_flow_exec(priv->xdev, &del, sizeof(del),
			XSC_FLOW_TBL_PCT_V4, XSC_IOCTL_OP_DEL);
}

int
xsc_create_ipat(struct rte_eth_dev *dev, uint16_t logic_in_port, uint16_t dst_info)
{
	struct xsc_flow_ipat_add {
		struct xsc_ipat_key key;
		struct xsc_ipat_action action;
	} add;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	memset(&add, 0, sizeof(add));

	add.key.logical_in_port = logic_in_port;
	add.action.dst_info = dst_info;
	add.action.vld = 1;
	return xsc_flow_exec(priv->xdev, &add, sizeof(add),
			XSC_FLOW_TBL_IPAT, XSC_IOCTL_OP_ADD);
}

int
xsc_destroy_ipat(struct rte_eth_dev *dev, uint16_t logic_in_port)
{
	struct xsc_flow_ipat_del {
		struct xsc_ipat_key key;
	} del;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	memset(&del, 0, sizeof(del));

	del.key.logical_in_port = logic_in_port;
	return xsc_flow_exec(priv->xdev, &del, sizeof(del),
			XSC_FLOW_TBL_IPAT, XSC_IOCTL_OP_DEL);
}

int
xsc_create_epat(struct rte_eth_dev *dev, uint16_t dst_info, uint8_t dst_port,
		uint16_t qpn_ofst, uint8_t qp_num)
{
	struct xsc_flow_epat_add {
		struct xsc_epat_key key;
		struct xsc_epat_action action;
	} add;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	memset(&add, 0, sizeof(add));
	add.key.dst_info = dst_info;
	add.action.dst_port = dst_port;
	add.action.vld = 1;
	add.action.rx_qp_id_ofst = qpn_ofst;
	add.action.qp_num = qp_num - 1;

	return xsc_flow_exec(priv->xdev, &add, sizeof(add),
			XSC_FLOW_TBL_EPAT, XSC_IOCTL_OP_ADD);
}

int
xsc_destroy_epat(struct rte_eth_dev *dev, uint16_t dst_info)
{
	struct xsc_flow_ipat_del {
		struct xsc_epat_key key;
	} del;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);

	memset(&del, 0, sizeof(del));

	del.key.dst_info = dst_info;
	return xsc_flow_exec(priv->xdev, &del, sizeof(del),
			XSC_FLOW_TBL_EPAT, XSC_IOCTL_OP_DEL);
}

