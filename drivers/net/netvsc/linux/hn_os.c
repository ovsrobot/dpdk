/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Microsoft Corporation
 */

#include <unistd.h>
#include <dirent.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>

#include <rte_ethdev.h>
#include <rte_alarm.h>

#include "hn_logs.h"
#include "hn_var.h"
#include "hn_os.h"

/* The max number of retry when hot adding a VF device */
#define NETVSC_MAX_HOTADD_RETRY 10

int eth_hn_os_dev_event(void)
{
	int ret;

	ret = rte_dev_event_monitor_start();
	if (ret)
		PMD_DRV_LOG(ERR, "Failed to start device event monitoring");

	return ret;
}

void netvsc_hotplug_retry(void *args)
{
	int ret;
	struct hn_data *hv = args;
	struct rte_eth_dev *dev = &rte_eth_devices[hv->port_id];
	struct rte_devargs *d = &hv->devargs;
	char buf[256];

	DIR *di;
	struct dirent *dir;
	struct ifreq req;
	struct rte_ether_addr eth_addr;
	int s;

	PMD_DRV_LOG(DEBUG, "%s: retry count %d",
		    __func__, hv->eal_hot_plug_retry);

	if (hv->eal_hot_plug_retry++ > NETVSC_MAX_HOTADD_RETRY)
		return;

	snprintf(buf, sizeof(buf), "/sys/bus/pci/devices/%s/net", d->name);
	di = opendir(buf);
	if (!di) {
		PMD_DRV_LOG(DEBUG, "%s: can't open directory %s, "
			    "retrying in 1 second", __func__, buf);
		goto retry;
	}

	while ((dir = readdir(di))) {
		/* Skip . and .. directories */
		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
			continue;

		/* trying to get mac address if this is a network device*/
		s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
		if (s == -1) {
			PMD_DRV_LOG(ERR, "Failed to create socket errno %d",
				    errno);
			break;
		}
		strlcpy(req.ifr_name, dir->d_name, sizeof(req.ifr_name));
		ret = ioctl(s, SIOCGIFHWADDR, &req);
		close(s);
		if (ret == -1) {
			PMD_DRV_LOG(ERR,
				    "Failed to send SIOCGIFHWADDR for device %s",
				    dir->d_name);
			break;
		}
		if (req.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
			closedir(di);
			return;
		}
		memcpy(eth_addr.addr_bytes, req.ifr_hwaddr.sa_data,
		       RTE_DIM(eth_addr.addr_bytes));

		if (rte_is_same_ether_addr(&eth_addr, dev->data->mac_addrs)) {
			PMD_DRV_LOG(NOTICE,
				    "Found matching MAC address, adding device %s network name %s",
				    d->name, dir->d_name);
			ret = rte_eal_hotplug_add(d->bus->name, d->name,
						  d->args);
			if (ret) {
				PMD_DRV_LOG(ERR,
					    "Failed to add PCI device %s",
					    d->name);
				break;
			}
		}
		/* When the code reaches here, we either have already added
		 * the device, or its MAC address did not match.
		 */
		closedir(di);
		return;
	}
	closedir(di);
retry:
	/* The device is still being initialized, retry after 1 second */
	rte_eal_alarm_set(1000000, netvsc_hotplug_retry, hv);
}
