/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

/*
 * Netlink-based control operations for the rtap PMD.
 *
 * Uses RTM_GETLINK / RTM_NEWLINK to replace ioctl() for interface
 * flag changes, MTU, MAC address, and statistics retrieval.
 *
 * Socket model:
 *   - Control socket (pmd->nlsk_fd): persistent per-device, opened
 *     at create time.  Used for flag changes, MTU, MAC operations.
 *   - LSC socket: persistent while enabled, subscribed to RTMGRP_LINK.
 *     Managed by rtap_intr.c via rtap_nl_open().
 *   - Stats queries (rtap_nl_get_stats): use an ephemeral socket
 *     opened on demand so they cannot block behind control operations.
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <rte_stdatomic.h>

#include "rtap.h"

/* Sequence number for netlink requests */
static RTE_ATOMIC(uint32_t) rtap_nl_seq;

/*
 * Open a netlink route socket.
 *
 * If groups is non-zero, the socket subscribes to those multicast
 * groups and is set non-blocking (for LSC notification).
 * If groups is zero, the socket is blocking (for control/query).
 *
 * Returns socket fd or -1 on failure.
 */
int
rtap_nl_open(unsigned int groups)
{
	int flags = SOCK_RAW | SOCK_CLOEXEC;
	int fd;
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = groups,
	};

	if (groups != 0)
		flags |= SOCK_NONBLOCK;

	fd = socket(AF_NETLINK, flags, NETLINK_ROUTE);
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
 * Send a netlink request and wait for acknowledgment.
 * Returns 0 on success, negative errno on failure.
 */
static int
rtap_nl_request(int fd, struct nlmsghdr *nlh)
{
	char buf[4096];
	ssize_t len;

	nlh->nlmsg_seq = rte_atomic_fetch_add_explicit(&rtap_nl_seq, 1,
						       rte_memory_order_relaxed);
	nlh->nlmsg_flags |= NLM_F_ACK;

	if (send(fd, nlh, nlh->nlmsg_len, 0) < 0)
		return -errno;

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0)
		return -errno;

	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(nh, (unsigned int)len))
		return -EBADMSG;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nh);

		return err->error;  /* 0 = success, negative = errno */
	}

	return -EBADMSG;
}

/*
 * Send a netlink request and receive a data response.
 * Returns length of response on success, negative errno on failure.
 */
static int
rtap_nl_query(int fd, struct nlmsghdr *nlh, char *buf, size_t buflen)
{
	ssize_t len;

	nlh->nlmsg_seq = rte_atomic_fetch_add_explicit(&rtap_nl_seq, 1,
						       rte_memory_order_relaxed);

	if (send(fd, nlh, nlh->nlmsg_len, 0) < 0)
		return -errno;

	len = recv(fd, buf, buflen, 0);
	if (len < 0)
		return -errno;

	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(nh, (unsigned int)len))
		return -EBADMSG;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nh);

		return err->error;
	}

	/* Detect truncated response */
	if (nh->nlmsg_len > (unsigned int)len)
		return -EBADMSG;

	return len;
}

/* Append a netlink attribute to a message. */
static void
rtap_nl_addattr(struct nlmsghdr *nlh, unsigned int maxlen,
		int type, const void *data, unsigned int datalen)
{
	unsigned int len = RTA_LENGTH(datalen);
	struct rtattr *rta;

	RTE_VERIFY(NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(len) <= maxlen);

	rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	if (datalen > 0)
		memcpy(RTA_DATA(rta), data, datalen);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(len);
}

/*
 * Get interface flags via RTM_GETLINK.
 * Returns 0 on success and sets *flags.
 */
int
rtap_nl_get_flags(int nlsk_fd, int if_index, unsigned int *flags)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req = {
		.nlh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.ifi = {
			.ifi_family = AF_UNSPEC,
			.ifi_index = if_index,
		},
	};
	char resp[4096];
	int ret;

	ret = rtap_nl_query(nlsk_fd, &req.nlh, resp, sizeof(resp));
	if (ret < 0)
		return ret;

	struct nlmsghdr *nh = (struct nlmsghdr *)resp;
	if (nh->nlmsg_type != RTM_NEWLINK)
		return -EBADMSG;

	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	*flags = ifi->ifi_flags;
	return 0;
}

/*
 * Change interface flags via RTM_NEWLINK.
 * 'flags' are set, 'mask' are cleared.
 */
int
rtap_nl_change_flags(int nlsk_fd, int if_index,
		     unsigned int flags, unsigned int mask)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req = {
		.nlh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_NEWLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.ifi = {
			.ifi_family = AF_UNSPEC,
			.ifi_index = if_index,
			.ifi_flags = flags,
			.ifi_change = mask,
		},
	};

	return rtap_nl_request(nlsk_fd, &req.nlh);
}

/*
 * Set MTU via RTM_NEWLINK.
 */
int
rtap_nl_set_mtu(int nlsk_fd, int if_index, uint16_t mtu)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[64];
	} req = {
		.nlh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_NEWLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.ifi = {
			.ifi_family = AF_UNSPEC,
			.ifi_index = if_index,
		},
	};
	unsigned int mtu32 = mtu;

	rtap_nl_addattr(&req.nlh, sizeof(req), IFLA_MTU, &mtu32, sizeof(mtu32));
	return rtap_nl_request(nlsk_fd, &req.nlh);
}

/*
 * Set MAC address via RTM_NEWLINK.
 */
int
rtap_nl_set_mac(int nlsk_fd, int if_index, const struct rte_ether_addr *addr)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[64];
	} req = {
		.nlh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_NEWLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.ifi = {
			.ifi_family = AF_UNSPEC,
			.ifi_index = if_index,
		},
	};

	rtap_nl_addattr(&req.nlh, sizeof(req), IFLA_ADDRESS,
			addr->addr_bytes, RTE_ETHER_ADDR_LEN);
	return rtap_nl_request(nlsk_fd, &req.nlh);
}

/*
 * Get MAC address via RTM_GETLINK.
 */
int
rtap_nl_get_mac(int nlsk_fd, int if_index, struct rte_ether_addr *addr)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req = {
		.nlh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.ifi = {
			.ifi_family = AF_UNSPEC,
			.ifi_index = if_index,
		},
	};
	char resp[4096];
	int ret;

	ret = rtap_nl_query(nlsk_fd, &req.nlh, resp, sizeof(resp));
	if (ret < 0)
		return ret;

	struct nlmsghdr *nh = (struct nlmsghdr *)resp;
	if (nh->nlmsg_type != RTM_NEWLINK)
		return -EBADMSG;

	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct rtattr *rta = (struct rtattr *)((char *)ifi + NLMSG_ALIGN(sizeof(*ifi)));
	int rtalen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));

	while (RTA_OK(rta, rtalen)) {
		if (rta->rta_type == IFLA_ADDRESS) {
			if (RTA_PAYLOAD(rta) == RTE_ETHER_ADDR_LEN) {
				memcpy(addr->addr_bytes, RTA_DATA(rta), RTE_ETHER_ADDR_LEN);
				return 0;
			}
		}
		rta = RTA_NEXT(rta, rtalen);
	}

	return -ENOENT;
}

/*
 * Get link statistics via RTM_GETLINK with IFLA_STATS64 attribute.
 * Opens an ephemeral socket to avoid blocking behind control operations.
 */
int
rtap_nl_get_stats(int if_index, struct rtnl_link_stats64 *stats)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req = {
		.nlh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
		},
		.ifi = {
			.ifi_family = AF_UNSPEC,
			.ifi_index = if_index,
		},
	};
	char resp[4096];
	int fd, ret;

	memset(stats, 0, sizeof(*stats));

	/* Use ephemeral socket so stats queries don't block */
	fd = rtap_nl_open(0);
	if (fd < 0)
		return fd;

	ret = rtap_nl_query(fd, &req.nlh, resp, sizeof(resp));
	close(fd);

	if (ret < 0)
		return ret;

	struct nlmsghdr *nh = (struct nlmsghdr *)resp;
	if (nh->nlmsg_type != RTM_NEWLINK)
		return -EBADMSG;

	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct rtattr *rta = (struct rtattr *)((char *)ifi + NLMSG_ALIGN(sizeof(*ifi)));
	int rtalen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));

	/* Parse attributes looking for IFLA_STATS64 */
	while (RTA_OK(rta, rtalen)) {
		if (rta->rta_type == IFLA_STATS64) {
			if (RTA_PAYLOAD(rta) >= sizeof(*stats)) {
				memcpy(stats, RTA_DATA(rta), sizeof(*stats));
				return 0;
			}
		}
		rta = RTA_NEXT(rta, rtalen);
	}

	return -ENOENT;
}

/*
 * Process incoming netlink messages for link state changes.
 * Called by rtap_intr.c when the LSC socket has data.
 */
void
rtap_nl_recv(int fd, struct rte_eth_dev *dev)
{
	struct rtap_pmd *pmd = dev->data->dev_private;
	char buf[4096];
	ssize_t len;

	while ((len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
		struct nlmsghdr *nh;

		for (nh = (struct nlmsghdr *)buf;
		     NLMSG_OK(nh, (unsigned int)len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_DONE)
				break;
			if (nh->nlmsg_type == NLMSG_ERROR)
				continue;
			if (nh->nlmsg_type != RTM_NEWLINK &&
			    nh->nlmsg_type != RTM_DELLINK)
				continue;

			struct ifinfomsg *ifi = NLMSG_DATA(nh);

			/* Only process messages for our interface */
			if (ifi->ifi_index != pmd->if_index)
				continue;

			if (nh->nlmsg_type == RTM_DELLINK) {
				PMD_LOG(INFO, "ifindex %d deleted", pmd->if_index);
				dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
				rte_eth_dev_callback_process(dev,
					RTE_ETH_EVENT_INTR_LSC, NULL);
			} else {
				bool was_up = dev->data->dev_link.link_status == RTE_ETH_LINK_UP;
				bool is_up = (ifi->ifi_flags & IFF_UP) &&
					     (ifi->ifi_flags & IFF_RUNNING);

				if (was_up != is_up) {
					PMD_LOG(DEBUG, "ifindex %d link %s",
						pmd->if_index, is_up ? "up" : "down");
					dev->data->dev_link.link_status =
						is_up ? RTE_ETH_LINK_UP : RTE_ETH_LINK_DOWN;
					rte_eth_dev_callback_process(dev,
						RTE_ETH_EVENT_INTR_LSC, NULL);
				}
			}
		}
	}
}
