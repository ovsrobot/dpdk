/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 ZTE Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

#include "zxdh_rawdev.h"
#include "zxdh_pci.h"

#define PCI_DEVICES_DIR          "/sys/bus/pci/devices"

#define BAR0_IDX                 (0)
#define BAR2_IDX                 (2)

#define IORESOURCE_MEM           (0x00000200)
#define FILE_FMT_NVAL            (2)

#define STR_BUFF_LEN             (128)

#define BYTES_NO_SWAP            (0)
#define BYTES_SWAP               (1)

#define PCI_CMD_OFFSET           (0x04)
#define PCI_CMD_BYTES            (2)
#define PCI_CMD_MSE_BIT          (1)
#define FPGA_VER_OFFSET          (0x420)
#define FPGA_VER_BYTES           (4)
#define BOM_ID_OFFSET            (0x424)
#define BOM_ID_BYTES             (1)
#define FPGA_PR_FLAG_OFFSET      (0x425)
#define FPGA_PR_FLAG_BYTES       (1)
#define BOARD_ID_OFFSET          (0x426)
#define BOARD_ID_BYTES           (2)
#define FPGA_MAKE_TIME_OFFSET    (0x428)
#define FPGA_MAKE_TIME_BYTES     (4)

#define PARA_PR_FLAG             (0)
#define PARA_FPGA_VER            (1)
#define PARA_FPGA_MAKE_TIME      (2)
#define PARA_BOARD_ID            (3)
#define PARA_BOM_ID              (4)
#define PARA_PCI_CMD             (5)

#define PCI_READ                 (0)
#define PCI_WRITE                (1)

struct zxdh_pci_dev gdev;

static int
zxdh_gdma_rw_pci_config(struct zxdh_pci_dev *dev, uint8_t rw, uint offset, uint count, uint8_t *buf)
{
	int fd = -1;
	uint res = 0;
	int ret = -1;
	char filename[FILE_PATH_LEN] = {0};

	snprintf(filename, sizeof(filename), "/proc/bus/pci/%02x/%02x.%d",
			dev->bus, dev->devid, dev->function);
	fd = open(filename, O_RDWR);
	if (fd < 0) {
		snprintf(filename, sizeof(filename), "/proc/bus/pci/%04x:%02x/%02x.%d",
				dev->domain, dev->bus, dev->devid, dev->function);
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			ZXDH_PMD_LOG(ERR, "Failed to open file:%s, fd:%d!", filename, fd);
			return -1;
		}
	}

	res = lseek(fd, offset, SEEK_SET);
	if (res != offset) {
		close(fd);
		ZXDH_PMD_LOG(ERR, "Failed to lseek pci, res:%d!", res);
		return -1;
	}

	if (rw == PCI_READ)
		ret = read(fd, buf, count);
	else
		ret = write(fd, buf, count);

	if (ret < 0) {
		close(fd);
		ZXDH_PMD_LOG(ERR, "Failed to rw pci:%d, ret:%d!", rw, ret);
		return -1;
	}

	close(fd);
	return 0;
}

static int
zxdh_gdma_cfg_space_read(struct zxdh_pci_dev *dev, uint8_t ParaType, uint *pParaVer)
{
	int ret = 0;
	uint8_t aRegVal[sizeof(uint)] = {0};
	uint8_t ucLoop = 0;
	uint8_t ucSwap = BYTES_NO_SWAP;
	uint dwRegOffset = 0;
	uint dwRegLen = 0;

	if ((dev == NULL) || (pParaVer == NULL)) {
		ZXDH_PMD_LOG(ERR, "Param is invalid!");
		return -EINVAL;
	}

	switch (ParaType) {
	case PARA_PR_FLAG:
		dwRegOffset = FPGA_PR_FLAG_OFFSET;
		dwRegLen    = FPGA_PR_FLAG_BYTES;
		ucSwap      = BYTES_NO_SWAP;
		break;
	case PARA_FPGA_VER:
		dwRegOffset = FPGA_VER_OFFSET;
		dwRegLen    = FPGA_VER_BYTES;
		ucSwap      = BYTES_NO_SWAP;
		break;
	case PARA_FPGA_MAKE_TIME:
		dwRegOffset = FPGA_MAKE_TIME_OFFSET;
		dwRegLen    = FPGA_MAKE_TIME_BYTES;
		ucSwap      = BYTES_NO_SWAP;
		break;
	case PARA_BOARD_ID:
		dwRegOffset = BOARD_ID_OFFSET;
		dwRegLen    = BOARD_ID_BYTES;
		ucSwap      = BYTES_NO_SWAP;
		break;
	case PARA_BOM_ID:
		dwRegOffset = BOM_ID_OFFSET;
		dwRegLen    = BOM_ID_BYTES;
		ucSwap      = BYTES_NO_SWAP;
		break;
	case PARA_PCI_CMD:
		dwRegOffset = PCI_CMD_OFFSET;
		dwRegLen    = PCI_CMD_BYTES;
		ucSwap      = BYTES_SWAP;
		break;
	default:
		ZXDH_PMD_LOG(ERR, "ParaType %u not support!", ParaType);
		return -EINVAL;
	}

	if (dwRegLen > sizeof(uint)) {
		ZXDH_PMD_LOG(ERR, "dwRegLen %u is invalid", dwRegLen);
		return -1;
	}

	*pParaVer = 0;
	ret = zxdh_gdma_rw_pci_config(dev, PCI_READ, dwRegOffset, dwRegLen, aRegVal);
	if (ret != 0) {
		ZXDH_PMD_LOG(ERR, "ParaType %u, zxdh_gdma_rw_pci_config failed!", ParaType);
		return ret;
	}

	if (ucSwap == BYTES_SWAP) {
		for (ucLoop = 0; ucLoop < dwRegLen; ucLoop++)
			*pParaVer = (*pParaVer << 8) | aRegVal[dwRegLen-1-ucLoop];
	} else {
		for (ucLoop = 0; ucLoop < dwRegLen; ucLoop++)
			*pParaVer = (*pParaVer << 8) | aRegVal[ucLoop];
	}

	return ret;
}

static int
zxdh_gdma_cfg_space_write(struct zxdh_pci_dev *dev, uint8_t ParaType, uint *pParaVer)
{
	int ret = 0;
	uint8_t aRegVal[sizeof(uint)] = {0};
	uint8_t ucLoop = 0;
	uint8_t ucSwap = BYTES_NO_SWAP;
	uint dwRegOffset = 0;
	uint dwRegLen = 0;

	if ((dev == NULL) || (pParaVer == NULL)) {
		ZXDH_PMD_LOG(ERR, "Param is invalid");
		return -EINVAL;
	}

	if (ParaType != PARA_PCI_CMD) {
		ZXDH_PMD_LOG(ERR, "ParaType %u not support!", ParaType);
		return -EINVAL;
	}

	dwRegOffset = PCI_CMD_OFFSET;
	dwRegLen = PCI_CMD_BYTES;
	ucSwap = BYTES_SWAP;

	if (dwRegLen > sizeof(uint)) {
		ZXDH_PMD_LOG(ERR, "dwRegLen %u is invalid", dwRegLen);
		return -1;
	}

	if (ucSwap == BYTES_SWAP) {
		for (ucLoop = 0; ucLoop < dwRegLen; ucLoop++)
			aRegVal[ucLoop] = (*pParaVer >> 8*ucLoop) & 0xff;
	} else {
		for (ucLoop = 0; ucLoop < dwRegLen; ucLoop++)
			aRegVal[ucLoop] = (*pParaVer >> 8*(dwRegLen-1-ucLoop)) & 0xff;
	}

	ret = zxdh_gdma_rw_pci_config(dev, PCI_WRITE, dwRegOffset, dwRegLen, aRegVal);
	if (ret != 0) {
		ZXDH_PMD_LOG(ERR, "ParaType %u, zxdh_gdma_rw_pci_config failed!", ParaType);
		return ret;
	}

	return ret;
}

static int
zxdh_gdma_str_split(char *string, int stringlen, char **tokens, int maxtokens, char delim)
{
	int loop = 0;
	int tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL) {
		ZXDH_PMD_LOG(ERR, "Param is invalid!");
		return -1;
	}

	for (loop = 0; loop < stringlen; loop++) {
		if (string[loop] == '\0' || tok >= maxtokens)
			break;

		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &string[loop];
		}

		if (string[loop] == delim) {
			string[loop] = '\0';
			tokstart = 1;
		}
	}

	return tok;
}

static int
zxdh_gdma_devfs_parse(const char *filename, unsigned long *val)
{
	FILE *f = NULL;
	char *end = NULL;
	char buf[STR_BUFF_LEN] = {0};

	f = fopen(filename, "r");
	if (f == NULL) {
		ZXDH_PMD_LOG(ERR, "Cannot open sysfs %s", filename);
		return -1;
	}

	if (fgets(buf, sizeof(buf), f) == NULL) {
		ZXDH_PMD_LOG(ERR, "Cannot read sysfs value %s", filename);
		fclose(f);
		return -1;
	}

	*val = strtoul(buf, &end, 0);
	if ((buf[0] == '\0') || (end == NULL) || (*end != '\n')) {
		ZXDH_PMD_LOG(ERR, "Cannot parse sysfs value %s", filename);
		fclose(f);
		return -1;
	}

	fclose(f);
	return 0;
}

static int
zxdh_gdma_resfs_parse(const char *filename, struct zxdh_pci_dev *dev)
{
	FILE *fp = NULL;
	char buf[STR_BUFF_LEN] = {0};
	uint8_t  loop = 0;
	uint64_t phys_addr = 0;
	uint64_t end_addr = 0;
	uint64_t flags = 0;
	int ret = 0;
	union pci_resource_info {
		struct {
			char *phys_addr;
			char *end_addr;
			char *flags;
		};
		char *ptrs[PCI_RESOURCE_FMT_NVAL];
	} res_info;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		ZXDH_PMD_LOG(ERR, "Failed to open file %s", filename);
		return -1;
	}

	for (loop = 0; loop < PCI_MAX_RESOURCE; loop++) {
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			ZXDH_PMD_LOG(ERR, "Failed to gets file %s", filename);
			goto err_exit;
		}

		ret = zxdh_gdma_str_split(buf, sizeof(buf), res_info.ptrs,
									PCI_RESOURCE_FMT_NVAL, ' ');
		if (ret != PCI_RESOURCE_FMT_NVAL) {
			ZXDH_PMD_LOG(ERR, "file %s:zxdh_gdma_str_split failed!", filename);
			goto err_exit;
		}
		errno = 0;
		phys_addr = strtoull(res_info.phys_addr, NULL, 16);
		end_addr  = strtoull(res_info.end_addr, NULL, 16);
		flags     = strtoull(res_info.flags, NULL, 16);

		if (errno != 0) {
			ZXDH_PMD_LOG(ERR, "file %s:bad resource format!", filename);
			goto err_exit;
		}

		if (flags & IORESOURCE_MEM) {
			if (loop == BAR0_IDX) {
				dev->bar_pa[BAR0_IDX] = phys_addr;
				dev->bar_len[BAR0_IDX] = end_addr - phys_addr + 1;
			}

			if (loop == BAR2_IDX) {
				dev->bar_pa[BAR2_IDX] = phys_addr;
				dev->bar_len[BAR2_IDX] = end_addr - phys_addr + 1;
				fclose(fp);
				return 0;
			}
		}
	}

	ZXDH_PMD_LOG(ERR, "file %s: Not found IO resource memory!", filename);

err_exit:
	fclose(fp);
	return -1;
}

static int
zxdh_gdma_pci_addr_parse(const char *buf, int buf_size, struct zxdh_pci_dev *dev)
{
	char *buf_copy = NULL;
	int ret = 0;
	union splitaddr {
		struct {
			char *domain;
			char *bus;
			char *devid;
			char *function;
		};
		char *str[PCI_FMT_NVAL];
	} splitaddr;

	buf_copy = strndup(buf, buf_size);
	if (buf_copy == NULL) {
		ZXDH_PMD_LOG(ERR, "buf %s: strndup failed!", buf);
		return -1;
	}

	/* first split on ':' */
	ret = zxdh_gdma_str_split(buf_copy, buf_size, splitaddr.str, PCI_FMT_NVAL, ':');
	if (ret != (PCI_FMT_NVAL - 1)) {
		ZXDH_PMD_LOG(ERR, "buf %s: zxdh_gdma_str_split failed!", buf);
		goto err_exit;
	}

	/* final split is on '.' between devid and function */
	splitaddr.function = strchr(splitaddr.devid, '.');
	if (splitaddr.function == NULL) {
		ZXDH_PMD_LOG(ERR, "buf %s: strchr failed!", buf);
		goto err_exit;
	}
	*splitaddr.function++ = '\0';

	/* now convert to int values */
	errno = 0;
	dev->domain = (uint16_t)strtoul(splitaddr.domain, NULL, 16);
	dev->bus = (uint8_t)strtoul(splitaddr.bus, NULL, 16);
	dev->devid = (uint8_t)strtoul(splitaddr.devid, NULL, 16);
	dev->function = (uint8_t)strtoul(splitaddr.function, NULL, 10);
	if (errno != 0) {
		ZXDH_PMD_LOG(ERR, "buf %s: bad format!", buf);
		goto err_exit;
	}
	free(buf_copy);
	return 0;

err_exit:
	free(buf_copy);
	return -1;
}

static int
zxdh_gdma_pci_dev_mmap(const char *filename, struct zxdh_pci_dev *dev, uint8_t bar_idx)
{
	int fd = -1;

	if (dev->bar_va[bar_idx] == NULL) {
		fd = open(filename, O_RDWR);
		if (fd < 0) {
			ZXDH_PMD_LOG(ERR, "Failed to open file %s", filename);
			return -1;
		}

		dev->bar_va[bar_idx] = mmap((void *)dev->bar_pa[bar_idx],
									dev->bar_len[bar_idx],
									PROT_READ | PROT_WRITE,
									MAP_SHARED, fd, 0);

		if (dev->bar_va[bar_idx] == MAP_FAILED) {
			ZXDH_PMD_LOG(ERR, "Failed to mmap file %s!", filename);
			goto err_exit;
		}
		close(fd);
	} else
		ZXDH_PMD_LOG(ERR, "BarVirtAddr is not NULL!");

	return 0;

err_exit:
	close(fd);
	return -1;
}

void
zxdh_gdma_pci_dev_munmap(void)
{
	if (gdev.bar_va[BAR0_IDX] != NULL) {
		munmap(gdev.bar_va[BAR0_IDX], gdev.bar_len[BAR0_IDX]);
		gdev.bar_va[BAR0_IDX] = NULL;
	}

	if (gdev.bar_va[BAR2_IDX] != NULL) {
		munmap(gdev.bar_va[BAR2_IDX], gdev.bar_len[BAR2_IDX]);
		gdev.bar_va[BAR2_IDX] = NULL;
	}
}

static int
zxdh_gdma_pci_mse_en(struct zxdh_pci_dev *dev)
{
	int ret = 0;
	uint RegVal = 0;

	ret = zxdh_gdma_cfg_space_read(dev, PARA_PCI_CMD, &RegVal);
	if (ret != 0) {
		ZXDH_PMD_LOG(ERR, "Failed to read %04x:%02x:%02x.%01x pci config space!",
						dev->domain, dev->bus, dev->devid, dev->function);
		return ret;
	}

	if ((RegVal & (1 << PCI_CMD_MSE_BIT)) == 0) {
		RegVal = RegVal | (1 << PCI_CMD_MSE_BIT);

		ret = zxdh_gdma_cfg_space_write(dev, PARA_PCI_CMD, &RegVal);
		if (ret != 0) {
			ZXDH_PMD_LOG(ERR, "Failed to write %04x:%02x:%02x.%01x pci config space!",
							dev->domain, dev->bus,
							dev->devid, dev->function);
			return ret;
		}
	}

	return ret;
}

int
zxdh_gdma_pci_scan(void)
{
	struct dirent *e = NULL;
	DIR *dir = NULL;
	char dirname[FILE_PATH_LEN] = {0};
	char filename[FILE_PATH_LEN] = {0};
	uint16_t vendor_id = 0;
	uint16_t device_id = 0;
	unsigned long tmp = 0;
	bool found = false;
	int ret = 0;

	dir = opendir(PCI_DEVICES_DIR);
	if (dir == NULL) {
		ZXDH_PMD_LOG(ERR, "Failed to opendir %s", PCI_DEVICES_DIR);
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] == '.')
			continue;

		memset(dirname, 0, FILE_PATH_LEN);
		snprintf(dirname, FILE_PATH_LEN, "%s/%s", PCI_DEVICES_DIR, e->d_name);

		snprintf(filename, sizeof(filename), "%s/vendor", dirname);
		ret = zxdh_gdma_devfs_parse(filename, &tmp);
		if (ret != 0)
			goto out;

		vendor_id = (uint16_t)tmp;

		snprintf(filename, sizeof(filename), "%s/device", dirname);
		ret = zxdh_gdma_devfs_parse(filename, &tmp);
		if (ret != 0)
			goto out;

		device_id = (uint16_t)tmp;

		if ((vendor_id == ZXDH_GDMA_VENDORID) && (device_id == ZXDH_GDMA_DEVICEID)) {
			found = true;
			break;
		}
	}

	if (found != true) {
		ZXDH_PMD_LOG(ERR, "Failed to found gdma pci dev");
		ret = -1;
		goto out;
	}

	gdev.vendor_id = vendor_id;
	gdev.device_id = device_id;
	memcpy(gdev.d_name, e->d_name, PCI_BUFF_LEN);
	memcpy(gdev.dirname, dirname, FILE_PATH_LEN);
	ZXDH_PMD_LOG(INFO, "Found gdma pci dev %s", e->d_name);

	/* Parse pci addr */
	ret = zxdh_gdma_pci_addr_parse(e->d_name, sizeof(e->d_name), &gdev);
	if (ret != 0)
		goto out;

	/* Enable MSE */
	ret = zxdh_gdma_pci_mse_en(&gdev);
	if (ret != 0)
		goto out;

	/* Get bar0 phyaddr and len */
	snprintf(filename, sizeof(filename), "%s/resource", dirname);
	ret = zxdh_gdma_resfs_parse(filename, &gdev);
	if (ret != 0)
		goto out;

	/* Mmap bar0 virtaddr */
	snprintf(filename, sizeof(filename), "%s/resource0", dirname);
	ret = zxdh_gdma_pci_dev_mmap(filename, &gdev, BAR0_IDX);
	if (ret != 0)
		goto out;

	ZXDH_PMD_LOG(INFO, "Found pci_scan success");

out:
	closedir(dir);
	return ret;
}
