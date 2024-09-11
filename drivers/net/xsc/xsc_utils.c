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
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/mman.h>

#include <rte_memcpy.h>
#include <rte_ethdev.h>
#include <ethdev_driver.h>

#include "xsc_log.h"
#include "xsc_utils.h"
#include "xsc_defs.h"

static int
xsc_get_ibdev_pci_addr(const char *dev_path, struct rte_pci_addr *pci_addr)
{
	FILE *file;
	char line[32];
	char path[PATH_MAX];
	int ret = -ENOENT;

	sprintf(path, "%s/device/uevent", dev_path);

	file = fopen(path, "rb");
	if (file == NULL) {
		PMD_DRV_LOG(ERR, "Failed to open file: (%s) ", path);
		return ret;
	}
	while (fgets(line, sizeof(line), file) == line) {
		size_t len = strlen(line);

		/* Truncate long lines. */
		if (len == (sizeof(line) - 1)) {
			while (line[(len - 1)] != '\n') {
				int n = fgetc(file);

				if (n == EOF)
					goto out;
				line[(len - 1)] = n;
			}
			/* No match for long lines. */
			continue;
		}
		/* Extract information. */
		if (sscanf(line,
			   "PCI_SLOT_NAME=%04x:%hhx:%hhx.%hhx",
			   &pci_addr->domain,
			   &pci_addr->bus,
			   &pci_addr->devid,
			   &pci_addr->function) == 4) {
			ret = 0;
			break;
		}
	}
out:
	fclose(file);
	return ret;
}

struct ibv_device *
xsc_get_ibv_device(const struct rte_pci_addr *addr)
{
	int ibv_num, i;
	struct ibv_device **ibv_list;
	struct ibv_device *ibv_match = NULL;
	struct rte_pci_addr ibv_pci_addr;

	ibv_list = ibv_get_device_list(&ibv_num);
	if (ibv_list == NULL)
		return NULL;

	for (i = 0; i < ibv_num; i++) {
		if (xsc_get_ibdev_pci_addr(ibv_list[i]->ibdev_path, &ibv_pci_addr) != 0)
			continue;
		if (rte_pci_addr_cmp(addr, &ibv_pci_addr) != 0)
			continue;
		ibv_match = ibv_list[i];
		PMD_DRV_LOG(DEBUG, "Finding device \"name:%s, %s, path:%s, %s\"..",
			    ibv_list[i]->name, ibv_list[i]->dev_name,
			    ibv_list[i]->dev_path, ibv_list[i]->ibdev_path);
		break;
	}
	ibv_free_device_list(ibv_list);

	if (ibv_match == NULL) {
		PMD_DRV_LOG(WARNING,
			    "No Verbs device matches PCI device " PCI_PRI_FMT,
			    addr->domain, addr->bus, addr->devid, addr->function);
	}

	return ibv_match;
}

int
xsc_get_ifname_by_pci_addr(struct rte_pci_addr *addr, char *ifname)
{
	DIR *dir;
	struct dirent *dent;
	unsigned int dev_type = 0;
	unsigned int dev_port_prev = ~0u;
	char match[IF_NAMESIZE] = "";
	char net_path[PATH_MAX];

	snprintf(net_path, sizeof(net_path), "%s/" PCI_PRI_FMT "/net",
		rte_pci_get_sysfs_path(), addr->domain, addr->bus,
		addr->devid, addr->function);

	dir = opendir(net_path);
	if (dir == NULL) {
		PMD_DRV_LOG(ERR, "Could not open %s", net_path);
		return -ENOENT;
	}

	while ((dent = readdir(dir)) != NULL) {
		char *name = dent->d_name;
		FILE *file;
		unsigned int dev_port;
		int r;
		char path[PATH_MAX];

		if ((name[0] == '.') &&
			((name[1] == '\0') ||
			 ((name[1] == '.') && (name[2] == '\0'))))
			continue;

		snprintf(path, sizeof(path), "%s/%s/%s",
			 net_path, name, (dev_type ? "dev_id" : "dev_port"));

		file = fopen(path, "rb");
		if (file == NULL) {
			if (errno != ENOENT)
				continue;
			/*
			 * Switch to dev_id when dev_port does not exist as
			 * is the case with Linux kernel versions < 3.15.
			 */
try_dev_id:
			match[0] = '\0';
			if (dev_type)
				break;
			dev_type = 1;
			dev_port_prev = ~0u;
			rewinddir(dir);
			continue;
		}
		r = fscanf(file, (dev_type ? "%x" : "%u"), &dev_port);
		fclose(file);
		if (r != 1)
			continue;
		/*
		 * Switch to dev_id when dev_port returns the same value for
		 * all ports. May happen when using a MOFED release older than
		 * 3.0 with a Linux kernel >= 3.15.
		 */
		if (dev_port == dev_port_prev)
			goto try_dev_id;
		dev_port_prev = dev_port;
		if (dev_port == 0)
			snprintf(match, IF_NAMESIZE, "%s", name);
	}
	closedir(dir);
	if (match[0] == '\0')
		return -ENOENT;

	snprintf(ifname, IF_NAMESIZE, "%s", match);
	return 0;
}

int
xsc_get_ifindex_by_ifname(const char *ifname, int *ifindex)
{
	struct ifreq ifr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1)
		return -EINVAL;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		close(sockfd);
		return -EINVAL;
	}

	*ifindex = ifr.ifr_ifindex;

	close(sockfd);
	return 0;
}

int
xsc_get_ifindex_by_pci_addr(struct rte_pci_addr *addr, int *ifindex)
{
	char ifname[IF_NAMESIZE];
	int ret;

	ret = xsc_get_ifname_by_pci_addr(addr, ifname);
	if (ret) {
		PMD_DRV_LOG(ERR, "Could not get ifname by pci address:" PCI_PRI_FMT,
			    addr->domain, addr->bus, addr->devid, addr->function);
		return ret;
	}

	ret = xsc_get_ifindex_by_ifname(ifname, ifindex);
	if (ret) {
		PMD_DRV_LOG(ERR, "Could not get ifindex by ifname:%s", ifname);
		return ret;
	}

	return 0;
}


static int
xsc_ifreq_by_ifname(const char *ifname, int req, struct ifreq *ifr)
{
	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	int ret = 0;

	if (sock == -1) {
		rte_errno = errno;
		return -rte_errno;
	}
	rte_strscpy(ifr->ifr_name, ifname, sizeof(ifr->ifr_name));
	ret = ioctl(sock, req, ifr);
	if (ret == -1) {
		rte_errno = errno;
		goto error;
	}
	close(sock);
	return 0;
error:
	close(sock);
	return -rte_errno;
}

int
xsc_get_mac(uint8_t *mac, uint32_t ifindex)
{
	struct ifreq request;
	struct ifreq *ifr = &request;
	char ifname[sizeof(ifr->ifr_name)];
	int ret;

	if (if_indextoname(ifindex, ifname) == NULL)
		return -rte_errno;

	ret = xsc_ifreq_by_ifname(ifname, SIOCGIFHWADDR, &request);
	if (ret)
		return ret;

	memcpy(mac, request.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);
	return 0;
}

int
xsc_get_mtu(uint16_t *mtu, uint32_t ifindex)
{
	struct ifreq request;
	struct ifreq *ifr = &request;
	char ifname[sizeof(ifr->ifr_name)];
	int ret;

	if (if_indextoname(ifindex, ifname) == NULL)
		return -rte_errno;

	ret = xsc_ifreq_by_ifname(ifname, SIOCGIFMTU, &request);
	if (ret)
		return ret;
	*mtu = request.ifr_mtu;
	return 0;
}

int
xsc_set_mtu(uint16_t mtu, uint32_t ifindex)
{
	struct ifreq request = { .ifr_mtu = mtu, };
	struct ifreq *ifr = &request;
	char ifname[sizeof(ifr->ifr_name)];

	if (if_indextoname(ifindex, ifname) == NULL)
		return -rte_errno;

	return xsc_ifreq_by_ifname(ifname, SIOCSIFMTU, &request);
}

int
xsc_mac_addr_add(struct rte_eth_dev *dev, struct rte_ether_addr *mac, uint32_t index)
{
	int i;
	rte_errno = EINVAL;

	if (index > XSC_MAX_MAC_ADDRESSES)
		return -rte_errno;

	if (rte_is_zero_ether_addr(mac))
		return -rte_errno;

	for (i = 0; i != XSC_MAX_MAC_ADDRESSES; ++i) {
		if (i == (int)index)
			continue;
		if (memcmp(&dev->data->mac_addrs[i], mac, sizeof(*mac)))
			continue;
		/* Address already configured elsewhere, return with error. */
		rte_errno = EADDRINUSE;
		return -rte_errno;
	}

	dev->data->mac_addrs[index] = *mac;
	return 0;
}

int
xsc_link_process(struct rte_eth_dev *dev __rte_unused,
		 uint32_t ifindex, unsigned int flags)
{
	struct ifreq request;
	struct ifreq *ifr = &request;
	char ifname[sizeof(ifr->ifr_name)];
	int ret;
	unsigned int keep = ~IFF_UP;

	if (if_indextoname(ifindex, ifname) == NULL)
		return -rte_errno;

	ret = xsc_ifreq_by_ifname(ifname, SIOCGIFFLAGS, &request);
	if (ret)
		return ret;

	request.ifr_flags &= keep;
	request.ifr_flags |= flags & ~keep;

	return xsc_ifreq_by_ifname(ifname, SIOCSIFFLAGS, &request);
}
