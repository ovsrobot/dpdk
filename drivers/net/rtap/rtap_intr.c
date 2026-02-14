/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <linux/rtnetlink.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <ethdev_driver.h>
#include <rte_interrupts.h>

#include "rtap.h"

/* Interrupt handler called by EAL when netlink socket is readable */
static void
rtap_lsc_handler(void *cb_arg)
{
	struct rte_eth_dev *dev = cb_arg;
	struct rtap_pmd *pmd = dev->data->dev_private;
	int fd = rte_intr_fd_get(pmd->intr_handle);

	if (fd >= 0)
		rtap_nl_recv(fd, dev);
}

/*
 * Enable or disable link state change interrupt.
 * When enabled, creates a netlink socket subscribed to RTMGRP_LINK
 * and registers it with the EAL interrupt handler.
 */
int
rtap_lsc_set(struct rte_eth_dev *dev, int set)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	unsigned int retry = 10;
	int ret;

	/* If LSC not configured, just disable if active */
	if (!dev->data->dev_conf.intr_conf.lsc) {
		if (rte_intr_fd_get(pmd->intr_handle) != -1)
			goto disable;
		return 0;
	}

	if (set) {
		int fd = rtap_nl_open(RTMGRP_LINK);
		if (fd < 0)
			return -1;

		rte_intr_fd_set(pmd->intr_handle, fd);
		ret = rte_intr_callback_register(pmd->intr_handle,
						 rtap_lsc_handler, dev);
		if (ret < 0) {
			PMD_LOG(ERR, "Failed to register LSC callback: %s",
				rte_strerror(-ret));
			close(fd);
			rte_intr_fd_set(pmd->intr_handle, -1);
			return ret;
		}
		return 0;
	}

disable:
	do {
		ret = rte_intr_callback_unregister(pmd->intr_handle,
						   rtap_lsc_handler, dev);
		if (ret >= 0) {
			break;
		} else if (ret == -EAGAIN && retry-- > 0) {
			rte_delay_ms(100);
		} else {
			PMD_LOG(ERR, "LSC callback unregister failed: %d", ret);
			break;
		}
	} while (true);

	if (rte_intr_fd_get(pmd->intr_handle) >= 0) {
		close(rte_intr_fd_get(pmd->intr_handle));
		rte_intr_fd_set(pmd->intr_handle, -1);
	}

	return 0;
}
