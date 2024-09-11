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
#include <sys/mman.h>

#include "xsc_log.h"
#include "xsc_utils.h"

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
