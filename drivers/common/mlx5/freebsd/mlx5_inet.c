/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include <err.h>
#include <errno.h>

#include <rte_errno.h>

#include "mlx5_inet.h"
#include "mlx5_common_log.h"
#include "mlx5_common_utils.h"
#include "mlx5_malloc.h"

/**
 * Check all multicast mode is enabled in driver through Socket.
 *
 * @param inetsk_fd
 *   Inet socket file descriptor.
 * @param ifname
 *   ifname buffer of mlx5_get_ifname(dev, ifname) function.
 * @param port_id
 *  port_id of the port .
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_inet_check_allmulti_flag(int inetsk_fd, char *ifname, uint16_t port_id)
{
	struct ifreq ifr;
	int value;

	if (inetsk_fd < 0)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(inetsk_fd, SIOCGIFFLAGS, (caddr_t)&ifr) < 0)
		return -errno;

	value = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
	if (!(value & IFF_ALLMULTI)) {
		DRV_LOG(WARNING,
			"port %u allmulti mode not enabled from kernel, "
			"please disable it from DPDK", port_id);
		return -1;
	}
	return 0;
}

/**
 * Enable promiscuous / all multicast mode through Socket.
 * We make a copy of ifreq to avoid SIOCIGIFFLAGS overwriting on the union
 * portion of the ifreq structure.
 *
 * @param inetsk_fd
 *   Inet socket file descriptor.
 * @param ifname_output
 *   ifname buffer of mlx5_get_ifname(dev, ifname) function.
 * @param flags
 *   IFF_PPROMISC for promiscuous, IFF_ALLMULTI for allmulti.
 * @param enable
 *   Nonzero to enable, disable otherwise.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_inet_device_flags(int inetsk_fd, char *ifname, int flags, int enable)
{
	struct ifreq ifr;
	int value;

	assert(!(flags & ~(IFF_PPROMISC)));
	if (inetsk_fd < 0)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(inetsk_fd, SIOCGIFFLAGS, (caddr_t)&ifr) < 0)
		return -errno;

	value = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
	if (enable)
		value |= flags;
	else
		value &= ~flags;

	ifr.ifr_flags = value & 0xffff;
	ifr.ifr_flagshigh = value >> 16;

	if (ioctl(inetsk_fd, SIOCSIFFLAGS, (caddr_t)&ifr) < 0)
		return -errno;

	return 0;
}

/**
 * Enable promiscuous mode through INET Socket.
 *
 * @param inetsk_fd
 *   Inet socket file descriptor.
 * @param ifname_output
 *   ifname buffer of mlx5_get_ifname(dev, ifname) function.
 * @param enable
 *   Nonzero to enable, disable otherwise.
 * @param port_id
 *   port_id of the interface
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_inet_promisc(int inetsk_fd, char *ifname, int enable, uint16_t port_id)
{
	int ret = mlx5_inet_device_flags(inetsk_fd, ifname, IFF_PPROMISC, enable);

	if (ret)
		DRV_LOG(DEBUG,
			"port %u cannot %s promisc mode: Socket error %s",
			port_id, enable ? "enable" : "disable",
			strerror(rte_errno));
	return ret;
}

/**
 * Modify the MAC address neighbour table with INET Socket.
 *
 * @param inetsk_fd
 *   Inet socket file descriptor.
 * @param ifname_output
 *   ifname buffer of mlx5_get_ifname(dev, ifname) function.
 * @param mac
 *   MAC address to consider.
 * @param port_id
 *   port_id of the interface
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_inet_mac_addr_modify(int inetsk_fd, char *ifname, struct rte_ether_addr *mac, uint16_t port_id)
{
	struct ifreq ifr;

	if (inetsk_fd < 0)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_LINK;
	memcpy(ifr.ifr_addr.sa_data, mac, RTE_ETHER_ADDR_LEN);
	ifr.ifr_addr.sa_len = RTE_ETHER_ADDR_LEN;

	if (ioctl(inetsk_fd, SIOCSIFLLADDR, &ifr) < 0) {
		rte_errno = errno;
		goto error;
	}

	return 0;
error:
	DRV_LOG(DEBUG,
		"port %u cannot add MAC address %02X:%02X:%02X:%02X:%02X:%02X %s",
		port_id,
		mac->addr_bytes[0], mac->addr_bytes[1],
		mac->addr_bytes[2], mac->addr_bytes[3],
		mac->addr_bytes[4], mac->addr_bytes[5],
		strerror(rte_errno));
	return -rte_errno;
}

/**
 * Set a MAC address.
 *
 * @param inetsk_fd
 *   Inet socket file descriptor.
 * @param ifname_output
 *   ifname buffer of mlx5_get_ifname(dev, ifname) function.
 * @param mac
 *   MAC address to register.
 * @param index
 *   MAC address index.
 * @param port_id
 *   port_id of the interface
 * @param mac_own
 *   Current MAC address.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_inet_mac_addr_set(int inetsk_fd, char *ifname,
		struct rte_ether_addr *mac, uint32_t index,
		uint16_t port_id, uint64_t *mac_own)
{
	int ret;

	ret = mlx5_inet_mac_addr_modify(inetsk_fd, ifname, mac, port_id);
	if (!ret)
		BITFIELD_SET(mac_own, index);
	if (ret == -EEXIST)
		return 0;
	return ret;
}

/**
 * DPDK callback to add a MAC address.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param mac_addr
 *   MAC address to register.
 * @param index
 *   MAC address index.
 * @param vmdq
 *   VMDq pool index to associate address with (ignored).
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
int
mlx5_inet_mac_addr_add(struct rte_ether_addr *mac __rte_unused,
			uint32_t index __rte_unused,
			uint32_t vmdq __rte_unused,
			uint16_t port_id)
{
	DRV_LOG(INFO, "port %u add MAC not supported in FreeBSD",
		port_id);
	return -EOPNOTSUPP;
}

/**
 * Before exiting, make interface LLADDR same as HWADDR
 *
 * @param inetsk_fd
 *   Inet socket file descriptor.
 * @param ifname_output
 *   ifname buffer of mlx5_get_ifname(dev, ifname) function.
 * @param lladdr
 * @param port_id
 *   port_id of the interface
 */
void
mlx5_inet_mac_addr_flush(int inetsk_fd, char *ifname,
			struct rte_ether_addr *lladdr,
			uint16_t port_id)
{
	struct ifreq ifr;

	if (inetsk_fd < 0)
		return;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_LINK;

	if (ioctl(inetsk_fd, SIOCGHWADDR, &ifr) < 0)
		return;

	if (memcmp(ifr.ifr_addr.sa_data, lladdr, RTE_ETHER_ADDR_LEN) == 0)
		return;

	mlx5_inet_mac_addr_modify(inetsk_fd, ifname,
				  (struct rte_ether_addr *)&ifr.ifr_addr.sa_data,
				  port_id);
}

/**
 * Remove a MAC address.
 *
 * @param mac
 *   MAC address to remove.
 * @param index
 *   MAC address index.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
void
mlx5_inet_mac_addr_remove(uint16_t port_id, uint32_t index __rte_unused)
{
	DRV_LOG(INFO,
		"port %u cannot remove MAC. Operation not supported in FreeBSD",
		port_id);
}

/* No bind required on this socket as there are no incoming messages */
int
mlx5_inet_init(void)
{
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		rte_errno = errno;
		return -rte_errno;
	}

	return s;
}
