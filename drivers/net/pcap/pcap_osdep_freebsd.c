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

/*
 * Map media subtype to speed in Mbps.
 * This handles common Ethernet media types.
 */
static uint32_t
media_subtype_to_speed(int subtype)
{
	switch (subtype) {
	case IFM_10_T:
	case IFM_10_2:
	case IFM_10_5:
	case IFM_10_STP:
	case IFM_10_FL:
		return 10;
	case IFM_100_TX:
	case IFM_100_FX:
	case IFM_100_T4:
	case IFM_100_VG:
	case IFM_100_T2:
		return 100;
	case IFM_1000_SX:
	case IFM_1000_LX:
	case IFM_1000_CX:
	case IFM_1000_T:
#ifdef IFM_1000_KX
	case IFM_1000_KX:
#endif
#ifdef IFM_1000_SGMII
	case IFM_1000_SGMII:
#endif
		return 1000;
#ifdef IFM_2500_T
	case IFM_2500_T:
#endif
#ifdef IFM_2500_X
	case IFM_2500_X:
#endif
#ifdef IFM_2500_KX
	case IFM_2500_KX:
#endif
		return 2500;
#ifdef IFM_5000_T
	case IFM_5000_T:
#endif
#ifdef IFM_5000_KR
	case IFM_5000_KR:
#endif
		return 5000;
	case IFM_10G_LR:
	case IFM_10G_SR:
	case IFM_10G_CX4:
	case IFM_10G_T:
	case IFM_10G_TWINAX:
	case IFM_10G_TWINAX_LONG:
	case IFM_10G_LRM:
	case IFM_10G_KX4:
	case IFM_10G_KR:
	case IFM_10G_CR1:
	case IFM_10G_ER:
	case IFM_10G_SFI:
		return 10000;
#ifdef IFM_20G_KR2
	case IFM_20G_KR2:
#endif
		return 20000;
	case IFM_25G_CR:
	case IFM_25G_KR:
	case IFM_25G_SR:
	case IFM_25G_LR:
#ifdef IFM_25G_ACC
	case IFM_25G_ACC:
#endif
#ifdef IFM_25G_AOC
	case IFM_25G_AOC:
#endif
#ifdef IFM_25G_ER
	case IFM_25G_ER:
#endif
#ifdef IFM_25G_T
	case IFM_25G_T:
#endif
		return 25000;
	case IFM_40G_CR4:
	case IFM_40G_SR4:
	case IFM_40G_LR4:
	case IFM_40G_KR4:
#ifdef IFM_40G_ER4
	case IFM_40G_ER4:
#endif
		return 40000;
	case IFM_50G_CR2:
	case IFM_50G_KR2:
#ifdef IFM_50G_SR2
	case IFM_50G_SR2:
#endif
#ifdef IFM_50G_LR2
	case IFM_50G_LR2:
#endif
#ifdef IFM_50G_KR
	case IFM_50G_KR:
#endif
#ifdef IFM_50G_SR
	case IFM_50G_SR:
#endif
#ifdef IFM_50G_CR
	case IFM_50G_CR:
#endif
#ifdef IFM_50G_LR
	case IFM_50G_LR:
#endif
#ifdef IFM_50G_FR
	case IFM_50G_FR:
#endif
		return 50000;
	case IFM_100G_CR4:
	case IFM_100G_SR4:
	case IFM_100G_KR4:
	case IFM_100G_LR4:
#ifdef IFM_100G_CR2
	case IFM_100G_CR2:
#endif
#ifdef IFM_100G_SR2
	case IFM_100G_SR2:
#endif
#ifdef IFM_100G_KR2
	case IFM_100G_KR2:
#endif
#ifdef IFM_100G_DR
	case IFM_100G_DR:
#endif
#ifdef IFM_100G_FR
	case IFM_100G_FR:
#endif
#ifdef IFM_100G_LR
	case IFM_100G_LR:
#endif
		return 100000;
#ifdef IFM_200G_CR4
	case IFM_200G_CR4:
#endif
#ifdef IFM_200G_SR4
	case IFM_200G_SR4:
#endif
#ifdef IFM_200G_KR4
	case IFM_200G_KR4:
#endif
#ifdef IFM_200G_LR4
	case IFM_200G_LR4:
#endif
#ifdef IFM_200G_FR4
	case IFM_200G_FR4:
#endif
#ifdef IFM_200G_DR4
	case IFM_200G_DR4:
#endif
		return 200000;
#ifdef IFM_400G_CR8
	case IFM_400G_CR8:
#endif
#ifdef IFM_400G_SR8
	case IFM_400G_SR8:
#endif
#ifdef IFM_400G_KR8
	case IFM_400G_KR8:
#endif
#ifdef IFM_400G_LR8
	case IFM_400G_LR8:
#endif
#ifdef IFM_400G_FR8
	case IFM_400G_FR8:
#endif
#ifdef IFM_400G_DR8
	case IFM_400G_DR8:
#endif
#ifdef IFM_400G_CR4
	case IFM_400G_CR4:
#endif
#ifdef IFM_400G_SR4
	case IFM_400G_SR4:
#endif
#ifdef IFM_400G_DR4
	case IFM_400G_DR4:
#endif
#ifdef IFM_400G_FR4
	case IFM_400G_FR4:
#endif
#ifdef IFM_400G_LR4
	case IFM_400G_LR4:
#endif
		return 400000;
#ifdef IFM_800G_CR8
	case IFM_800G_CR8:
#endif
#ifdef IFM_800G_SR8
	case IFM_800G_SR8:
#endif
#ifdef IFM_800G_DR8
	case IFM_800G_DR8:
#endif
#ifdef IFM_800G_FR8
	case IFM_800G_FR8:
#endif
#ifdef IFM_800G_LR8
	case IFM_800G_LR8:
#endif
		return 800000;
	default:
		return 0;
	}
}

int
osdep_iface_link_get(const char *if_name, struct osdep_iface_link *link)
{
	struct ifmediareq ifmr;
	struct ifreq ifr;
	int if_fd;
	int subtype;

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
			subtype = IFM_SUBTYPE(ifmr.ifm_current);
			link->link_speed = media_subtype_to_speed(subtype);

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
