/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 * All rights reserved.
 */

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <rte_memcpy.h>
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

	rte_memcpy(mac->addr_bytes, ifr.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);

	close(if_fd);
	return 0;
}

int
osdep_iface_mtu_set(int ifindex, uint16_t mtu)
{
	char ifname[IFNAMSIZ];

	if (if_indextoname(ifindex, ifname) == NULL)
		return -errno;

	int s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -errno;

	struct ifreq ifr = { .ifr_mtu = mtu };
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	int ret = ioctl(s, SIOCSIFMTU, &ifr);
	close(s);

	return (ret < 0) ? -errno : 0;
}
