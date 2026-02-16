/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <rte_string_fns.h>

#include "pcap_osdep.h"

int
osdep_iface_index_get(const char *name)
{
	return if_nametoindex(name);
}

int
osdep_iface_mac_get(const char *if_name, struct rte_ether_addr *mac)
{
	struct ifreq ifr;
	int if_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (if_fd == -1)
		return -1;

	rte_strscpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(if_fd, SIOCGIFHWADDR, &ifr)) {
		close(if_fd);
		return -1;
	}

	memcpy(mac->addr_bytes, ifr.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);

	close(if_fd);
	return 0;
}

/*
 * Get link speed, duplex, and autoneg using ETHTOOL_GLINKSETTINGS.
 *
 * ETHTOOL_GLINKSETTINGS was introduced in kernel 4.7 and supports
 * speeds beyond 65535 Mbps (up to 800 Gbps and beyond).
 * DPDK requires kernel 4.19 or later, so this interface is always available.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
get_link_settings(int fd, struct ifreq *ifr, struct osdep_iface_link *link)
{
	struct ethtool_link_settings probe = { };
	struct ethtool_link_settings *req;
	size_t req_size;
	int nwords;
	int ret = -1;

	/* First call with nwords = 0 to get the required size */
	probe.cmd = ETHTOOL_GLINKSETTINGS;
	ifr->ifr_data = (void *)&probe;

	if (ioctl(fd, SIOCETHTOOL, ifr) < 0)
		return -1;

	/* Kernel returns negative nwords on first call */
	if (probe.link_mode_masks_nwords >= 0)
		return -1;

	nwords = -probe.link_mode_masks_nwords;

	/* Bounds check */
	if (nwords == 0 || nwords > 127)
		return -1;

	/* Second call with correct nwords - need space for 3 link mode masks */
	req_size = sizeof(*req) + 3 * nwords * sizeof(uint32_t);
	req = malloc(req_size);
	if (req == NULL)
		return -1;

	memset(req, 0, req_size);
	req->cmd = ETHTOOL_GLINKSETTINGS;
	req->link_mode_masks_nwords = nwords;
	ifr->ifr_data = (void *)req;

	if (ioctl(fd, SIOCETHTOOL, ifr) < 0)
		goto out;

	/* Speed is in Mbps, directly usable */
	link->link_speed = req->speed;

	/* Handle special values */
	if (link->link_speed == (uint32_t)SPEED_UNKNOWN ||
	    link->link_speed == (uint32_t)-1)
		link->link_speed = 0;

	switch (req->duplex) {
	case DUPLEX_FULL:
		link->link_duplex = 1;
		break;
	case DUPLEX_HALF:
		link->link_duplex = 0;
		break;
	default:
		link->link_duplex = 1;  /* Default to full duplex */
		break;
	}

	link->link_autoneg = (req->autoneg == AUTONEG_ENABLE) ? 1 : 0;
	ret = 0;
out:
	free(req);
	return ret;
}

int
osdep_iface_link_get(const char *if_name, struct osdep_iface_link *link)
{
	struct ifreq ifr;
	int if_fd;

	memset(link, 0, sizeof(*link));

	if_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (if_fd == -1)
		return -1;

	/* Get interface flags to determine link status */
	rte_strscpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(if_fd, SIOCGIFFLAGS, &ifr) == 0) {
		/*
		 * IFF_UP means administratively up
		 * IFF_RUNNING means operationally up (carrier detected)
		 */
		if ((ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING))
			link->link_status = 1;
	}

	rte_strscpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (get_link_settings(if_fd, &ifr, link) < 0) {
		/*
		 * ethtool failed - interface may not support it
		 * (e.g., virtual interfaces like veth, lo).
		 * Use reasonable defaults.
		 */
		link->link_speed = 0;
		link->link_duplex = 1;  /* Assume full duplex */
		link->link_autoneg = 0;
	}

	close(if_fd);
	return 0;
}
