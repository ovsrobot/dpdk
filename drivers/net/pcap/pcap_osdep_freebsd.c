/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 * All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include "pcap_osdep.h"

/*
 * Userspace implementation of ifmedia_baudrate().
 * The kernel function is not exported to userspace, so we implement
 * our own using the IFM_BAUDRATE_DESCRIPTIONS table from if_media.h.
 */
static uint64_t
ifmedia_baudrate_user(int mword)
{
	static const struct ifmedia_baudrate descs[] =
		IFM_BAUDRATE_DESCRIPTIONS;
	const struct ifmedia_baudrate *desc;

	for (desc = descs; desc->ifmb_word != 0; desc++) {
		if (IFM_TYPE_MATCH(desc->ifmb_word, mword))
			return desc->ifmb_baudrate;
	}
	return 0;
}

int
osdep_iface_index_get(const char *name)
{
	return if_nametoindex(name);
}

int
osdep_iface_mac_get(const char *if_name, struct rte_ether_addr *mac)
{
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;
	int mib[6];
	size_t len = 0;
	char *buf;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_LINK;
	mib[4] = NET_RT_IFLIST;
	mib[5] = if_nametoindex(if_name);

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		return -1;

	if (len == 0)
		return -1;

	buf = malloc(len);
	if (!buf)
		return -1;

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		free(buf);
		return -1;
	}
	ifm = (struct if_msghdr *)buf;
	sdl = (struct sockaddr_dl *)(ifm + 1);

	memcpy(mac->addr_bytes, LLADDR(sdl), RTE_ETHER_ADDR_LEN);

	free(buf);
	return 0;
}

int
osdep_iface_link_get(const char *if_name, struct osdep_iface_link *link)
{
	struct ifmediareq ifmr;
	struct ifreq ifr;
	uint64_t baudrate;
	int if_fd;

	memset(link, 0, sizeof(*link));

	if_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (if_fd == -1)
		return -1;

	/* Get interface flags to determine administrative status */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(if_fd, SIOCGIFFLAGS, &ifr) == 0) {
		if (ifr.ifr_flags & IFF_UP)
			link->link_status = 1;
	}

	/* Get media status for speed, duplex, and link state */
	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, if_name, sizeof(ifmr.ifm_name));

	if (ioctl(if_fd, SIOCGIFMEDIA, &ifmr) == 0) {
		/* Check if link is actually active */
		if (!(ifmr.ifm_status & IFM_ACTIVE))
			link->link_status = 0;

		/* Only parse media if we have a valid current media type */
		if (ifmr.ifm_current != 0 && IFM_TYPE(ifmr.ifm_current) == IFM_ETHER) {
			/* Use userspace baudrate lookup */
			baudrate = ifmedia_baudrate_user(ifmr.ifm_current);
			link->link_speed = baudrate / 1000000;

			/* Check duplex - FDX option means full duplex */
			if (IFM_OPTIONS(ifmr.ifm_current) & IFM_FDX)
				link->link_duplex = 1;
			else
				link->link_duplex = 0;
		} else {
			/* Default to full duplex if we can't determine */
			link->link_duplex = 1;
		}

		/* Check autonegotiation status */
		link->link_autoneg = (ifmr.ifm_current & IFM_AUTO) ? 1 : 0;
	} else {
		/*
		 * SIOCGIFMEDIA failed - interface may not support it.
		 * Default to reasonable values.
		 */
		link->link_duplex = 1;  /* Assume full duplex */
		link->link_autoneg = 0;
	}

	close(if_fd);
	return 0;
}
