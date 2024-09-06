/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "xsc_log.h"
#include "xsc_dev.h"
#include "xsc_ctrl.h"

int
xsc_ioctl(struct xsc_dev *dev, int cmd, int opcode,
	  void *data_in, int in_len, void *data_out, int out_len)
{
	struct xsc_ioctl_hdr *hdr;
	int data_len = RTE_MAX(in_len, out_len);
	int alloc_len = sizeof(struct xsc_ioctl_hdr) + data_len;
	int ret = 0;

	hdr = rte_zmalloc(NULL, alloc_len, RTE_CACHE_LINE_SIZE);
	if (hdr == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate xsc ioctl cmd memory");
		return -ENOMEM;
	}

	hdr->check_field = XSC_IOCTL_CHECK_FIELD;
	hdr->attr.opcode = opcode;
	hdr->attr.length = data_len;
	hdr->attr.error = 0;

	if (data_in != NULL && in_len > 0)
		rte_memcpy(hdr + 1, data_in, in_len);

	ret = ioctl(dev->ctrl_fd, cmd, hdr);
	if (ret == 0) {
		if (hdr->attr.error != 0)
			ret = hdr->attr.error;
		else if (data_out != NULL && out_len > 0)
			rte_memcpy(data_out, hdr + 1, out_len);
	}

	rte_free(hdr);
	return ret;
}

int
xsc_mailbox_exec(struct xsc_dev *dev, void *data_in,
		 int in_len, void *data_out, int out_len)
{
	/* ignore opcode in hdr->attr when cmd = XSC_IOCTL_CMDQ_RAW */
	return xsc_ioctl(dev, XSC_IOCTL_CMDQ_RAW, 0, data_in, in_len, data_out, out_len);
}