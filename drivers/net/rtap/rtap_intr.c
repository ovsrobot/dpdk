/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

#include <rte_interrupts.h>

#include "rtap.h"

/*
 * Create a netlink socket subscribed to link state change events.
 * Returns socket fd or -1 on failure.
 */
static int
rtap_netlink_init(unsigned int groups)
{
	int fd;
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = groups,
	};

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    NETLINK_ROUTE);
	if (fd < 0) {
		PMD_LOG_ERRNO(ERR, "netlink socket");
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		PMD_LOG_ERRNO(ERR, "netlink bind");
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Drain all pending netlink messages from socket.
 * For each RTM_NEWLINK/RTM_DELLINK that matches our interface,
 * update link status.
 */
static void
rtap_netlink_recv(int fd, struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	unsigned int if_index = if_nametoindex(pmd->ifname);
	char buf[4096];
	ssize_t len;

	while ((len = recv(fd, buf, sizeof(buf), 0)) > 0) {
		for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
		     NLMSG_OK(nh, (unsigned int)len);
		     nh = NLMSG_NEXT(nh, len)) {
			struct ifinfomsg *ifi;

			if (nh->nlmsg_type != RTM_NEWLINK &&
			    nh->nlmsg_type != RTM_DELLINK)
				continue;

			ifi = NLMSG_DATA(nh);
			if ((unsigned int)ifi->ifi_index != if_index)
				continue;

			/* Link state changed for our interface */
			rtap_link_update(dev, 0);
		}
	}
}

/* Interrupt handler called by EAL when netlink socket is readable */
static void
rtap_lsc_handler(void *cb_arg)
{
	struct rte_eth_dev *dev = cb_arg;
	struct rtap_pmd *pmd = dev->data->dev_private;
	int fd = rte_intr_fd_get(pmd->intr_handle);

	if (fd >= 0)
		rtap_netlink_recv(fd, dev);
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
	int ret;

	/* If LSC not configured, just disable if active */
	if (!dev->data->dev_conf.intr_conf.lsc) {
		if (rte_intr_fd_get(pmd->intr_handle) != -1)
			goto disable;
		return 0;
	}

	if (set) {
		int fd = rtap_netlink_init(RTMGRP_LINK);
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
	unsigned int retry = 10;
	do {
		ret = rte_intr_callback_unregister(pmd->intr_handle,
						   rtap_lsc_handler, dev);
		if (ret >= 0)
			break;
		if (ret == -EAGAIN && retry-- > 0)
			rte_delay_ms(100);
		else {
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
