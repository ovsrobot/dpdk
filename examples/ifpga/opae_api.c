/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <glob.h>
#include <unistd.h>
#include <sys/stat.h>
#include <rte_eal.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_rawdev_pmd.h>
#include "rte_pmd_ifpga.h"
#include "opae_api.h"


int opae_log_level;
FILE *opae_log_file;

static opae_api_version api_ver = {21, 5, 0};
static int eal_inited;
static uint32_t dev_aer[2] = {0};

static const char * const log_level_name[] = {"CRITICAL", "ERROR",
	"WARNING", "INFORMATION", "DEBUG"};
static const char * const proc_type_name[] = {"NON-DPDK", "PRIMARY",
	"SECONDARY"};
static const char * const platform_name[] = {"Vista Creek", "Rush Creek",
	"Darby Creek", "Lightning Creek"};
static const char * const release_name[] = {"Pre-Alpha", "Alpha", "Beta", "PV"};
static const char * const interface_type[] = {"8x10G", "4x25G", "2x1x25G",
	"4x25G+2x25G", "2x2x25G", "2x1x25Gx2FVL", "1x2x25G"};

void opae_get_api_version(opae_api_version *version)
{
	if (version)
		memcpy(version, &api_ver, sizeof(opae_api_version));
	opae_log_info("API version is %u.%u.%u\n",
		api_ver.major, api_ver.minor, api_ver.micro);
}

int opae_set_log_level(int level)
{
	if ((level >= OPAE_LOG_API) && (level <= OPAE_LOG_DEBUG))
		opae_log_level = level;
	opae_log_api("Current log level is %s\n",
		log_level_name[opae_log_level]);
	return opae_log_level;
}

int opae_set_log_file(char *path, int clean)
{
	FILE *f = NULL;
	time_t start;
	struct tm *lt = NULL;

	if (path) {
		if (clean)
			f = fopen(path, "w+");
		else
			f = fopen(path, "a+");

		if (f) {
			if (opae_log_file) {
				fclose(opae_log_file);
				opae_log_file = NULL;
			}
			time(&start);
			lt = localtime(&start);
			if (lt)
				fprintf(f, "================%d-%02d-%02d "
					"%02d:%02d:%02d================\n",
					1900 + lt->tm_year, 1 + lt->tm_mon,
					lt->tm_mday,
					lt->tm_hour, lt->tm_min, lt->tm_sec);
			fflush(f);
			opae_log_file = f;
		} else {
			opae_log_err("failed to open log file \'%s\'\n", path);
			return -1;
		}
	} else {
		if (opae_log_file) {
			fclose(opae_log_file);
			opae_log_file = NULL;
		}
	}

	return 0;
}

int opae_get_image_info(const char *image, opae_img_info *info)
{
	int fd = -1;
	off_t file_size = 0;
	opae_img_hdr hdr;
	ssize_t read_size = 0;
	int ret = 0;

	if (!image || !info) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	fd = open(image, O_RDONLY);
	if (fd < 0) {
		opae_log_err("Failed to open \'%s\' for RD [e:%s]\n",
			image, strerror(errno));
		return -EIO;
	}

	file_size = lseek(fd, 0, SEEK_END);
	if (file_size < (OPAE_IMG_HDR_SIZE + OPAE_IMG_PL_MIN_SIZE)) {
		opae_log_err("Size of \'%s\' is less than expected [e:%u]\n",
			image, OPAE_IMG_HDR_SIZE + OPAE_IMG_PL_MIN_SIZE);
		ret = -EINVAL;
		goto close_fd;
	}

	/* read image header */
	lseek(fd, 0, SEEK_SET);
	read_size = read(fd, (void *)&hdr, sizeof(opae_img_hdr));
	if (read_size < 0) {
		opae_log_err("Failed to read from \'%s\' [e:%s]\n",
			image, strerror(errno));
		ret = -EIO;
		goto close_fd;
	}
	if ((size_t)read_size != sizeof(opae_img_hdr)) {
		opae_log_err("Read length %zd is not expected [e:%zu]\n",
			read_size, sizeof(opae_img_hdr));
		ret = -EIO;
		goto close_fd;
	}

	info->total_len = file_size;
	/* check signed image header */
	if (hdr.magic == OPAE_IMG_BLK0_MAGIC) {
		info->type = OPAE_IMG_TYPE(hdr.payload_type);
		info->subtype = OPAE_IMG_SUBTYPE(hdr.payload_type);
		info->payload_offset = OPAE_IMG_HDR_SIZE;
		info->payload_len = hdr.payload_len;
	} else {
		opae_log_err("Image \'%s\' can not be recognized\n", image);
		ret = -EINVAL;
	}
close_fd:
	close(fd);
	return ret;
}

static int write_file(char *path, char *buf, int size)
{
	int fd = -1;
	ssize_t n = 0;

	if (!path || !buf || (size <= 0))
		return -EINVAL;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		opae_log_err("Failed to open \'%s\' for WR [e:%s]\n",
			path, strerror(errno));
		return -EIO;
	}
	opae_log_dbg("Write \"%s\" to \'%s\'\n", buf, path);
	n = write(fd, buf, size);
	if (n < size)  {
		opae_log_err("Failed to write to \'%s\' [e:%s]\n",
			path, strerror(errno));
		close(fd);
		return -EIO;
	}
	close(fd);

	return 0;
}

static int read_file(char *path, char *buf, int size)
{
	int fd = -1;
	ssize_t n = 0;

	if (!path || !buf || (size <= 0))
		return -EINVAL;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		opae_log_err("Failed to open \'%s\' for RD [e:%s]\n",
			path, strerror(errno));
		return -EIO;
	}
	n = read(fd, buf, size);
	if (n < 0)  {
		opae_log_err("Failed to read from \'%s\' [e:%s]\n",
			path, strerror(errno));
		close(fd);
		return -EIO;
	}
	close(fd);

	if (n > 0)
		buf[n-1] = 0;

	opae_log_dbg("Read \"%s\" from \'%s\'\n", buf, path);
	return 0;
}

int opae_get_proc_type(void)
{
	int type = -1;

	if (eal_inited) {
		if (rte_eal_process_type() == RTE_PROC_PRIMARY)
			type = 0;
		else
			type = 1;
	}
	opae_log_info("Current process type is %s\n", proc_type_name[type+1]);

	return type;
}

static bool check_eal(int inited)
{
	if (!eal_inited) {
		if (inited) {
			opae_log_warn("EAL is not initialized\n");
			return 0;
		}
	} else {
		if (!inited) {
			opae_log_warn("EAL is already initialized\n");
			return 0;
		}
	}

	return 1;
}

int opae_init_eal(int argc, char **argv)
{
	int ret = 0;

	if (!check_eal(0))
		return ret;

	opae_log_level = OPAE_LOG_ERR;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		if (rte_errno == EALREADY) {
			eal_inited = 1;
			return 0;
		}
		opae_log_err("Cannot initialize EAL [e:%d]\n", ret);
		if (rte_eal_cleanup())
			opae_log_warn("EAL could not release all resources\n");
	} else {
		eal_inited = 1;
		opae_log_info("Initialize EAL done\n");
	}

	return ret;
}

int opae_cleanup_eal(void)
{
	int ret = 0;

	if (!check_eal(1))
		return -EPERM;

	rte_pmd_ifpga_cleanup();

	ret = rte_eal_cleanup();
	if (ret)
		opae_log_err("Failed to cleanup EAL [e:%d]\n", ret);

	if (opae_log_file) {
		fclose(opae_log_file);
		opae_log_file = NULL;
	}

	return ret;
}

static int compare_pci_id(opae_pci_id *id, opae_pci_id *expected_id)
{
	if ((expected_id->class_id != BIT_SET_32) &&
		(expected_id->class_id != id->class_id))
		return -1;
	if ((expected_id->vendor_id != BIT_SET_16) &&
		(expected_id->vendor_id != id->vendor_id))
		return -1;
	if ((expected_id->device_id != BIT_SET_16) &&
		(expected_id->device_id != id->device_id))
		return -1;
	if ((expected_id->subsystem_vendor_id != BIT_SET_16) &&
		(expected_id->subsystem_vendor_id != id->subsystem_vendor_id))
		return -1;
	if ((expected_id->subsystem_device_id != BIT_SET_16) &&
		(expected_id->subsystem_device_id != id->subsystem_device_id))
		return -1;

	return 0;
}

static int parse_sysfs_value(char *node, uint32_t *val)
{
	char buf[16];
	char *end = NULL;
	int ret = 0;

	ret = read_file(node, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	*val = (uint32_t)strtoul(buf, &end, 0);
	return 0;
}

static int get_pci_id(const char *dev_path, opae_pci_id *id)
{
	char path[PATH_MAX] = {0};
	uint32_t tmp;

	if (!dev_path || !id)
		return -EINVAL;

	snprintf(path, sizeof(path), "%s/vendor", dev_path);
	if (parse_sysfs_value(path, &tmp) < 0)
		return -ENODEV;
	id->vendor_id = (uint16_t)tmp;

	snprintf(path, sizeof(path), "%s/device", dev_path);
	if (parse_sysfs_value(path, &tmp) < 0)
		return -ENODEV;
	id->device_id = (uint16_t)tmp;

	snprintf(path, sizeof(path), "%s/subsystem_vendor", dev_path);
	if (parse_sysfs_value(path, &tmp) < 0)
		return -ENODEV;
	id->subsystem_vendor_id = (uint16_t)tmp;

	snprintf(path, sizeof(path), "%s/subsystem_device", dev_path);
	if (parse_sysfs_value(path, &tmp) < 0)
		return -ENODEV;
	id->subsystem_device_id = (uint16_t)tmp;

	snprintf(path, sizeof(path), "%s/class", dev_path);
	if (parse_sysfs_value(path, &tmp) < 0)
		return -ENODEV;
	id->class_id = (uint32_t)tmp & RTE_CLASS_ANY_ID;

	return 0;
}

static int extract_path(char *in, int ridx, char *out, uint32_t size)
{
	char src[PATH_MAX] = {0};
	char *p = NULL;
	int ret = 0;

	if (!in || (strlen(in) > PATH_MAX) || (ridx < 0) || !out)
		return -EINVAL;

	strncpy(src, in, sizeof(src));
	*out = 0;

	while (1) {
		p = strrchr(src, '/');
		if (p) {
			*p++ = 0;
			if (*p) {
				if (ridx-- <= 0) {
					if (size > strlen(p)) {
						strncpy(out, p, size);
						ret = strlen(p);
					}
					break;
				}
			}
		} else {
			break;
		}
	}

	return ret;
}

int opae_enumerate(opae_pci_id *filter, pcidev_id list, int size)
{
	DIR *dir = NULL;
	struct dirent *dirent = NULL;
	char path[PATH_MAX] = {0};
	opae_pci_id id;
	int n = 0;

	if (!filter || (size < 0) || (!list && (size > 0))) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	dir = opendir(rte_pci_get_sysfs_path());
	if (!dir) {
		opae_log_err("Failed to open \'%s\'\n",
			rte_pci_get_sysfs_path());
		return -EINVAL;
	}
	while ((dirent = readdir(dir))) {
		if (!strcmp(dirent->d_name, "."))
			continue;
		if (!strcmp(dirent->d_name, ".."))
			continue;

		snprintf(path, PATH_MAX, "%s/%s", rte_pci_get_sysfs_path(),
			dirent->d_name);
		if (get_pci_id(path, &id) < 0)
			continue;
		if (compare_pci_id(&id, filter) < 0)
			continue;

		if (n++ < size) {
			snprintf(list->bdf, sizeof(list->bdf), "%s",
				dirent->d_name);
			list++;
		}
	}
	closedir(dir);

	return n;
}

static int get_driver(pcidev_id id, char *drv_name, uint32_t size)
{
	char path[PATH_MAX] = {0};
	char link[PATH_MAX] = {0};
	int ret = 0;

	if (!id || !drv_name) {
		ret = -EINVAL;
		goto end;
	}
	size--;   /* reserve one byte for the end of string */

	snprintf(path, PATH_MAX, "%s/%s/driver",
		rte_pci_get_sysfs_path(), id->bdf);
	ret = readlink(path, link, PATH_MAX);
	if (ret >= PATH_MAX) {
		opae_log_err("Link path too long [%d]\n", ret);
		ret = -ENAMETOOLONG;
		goto end;
	}
	if (ret > 0) {
		ret = extract_path(link, 0, drv_name, size);
	} else {
		*drv_name = 0;
		opae_log_info("No link path for \'%s\'\n", path);
		ret = 0;
	}

end:
	if (ret < 0)
		opae_log_err("Failed to get driver of %s\n", id->bdf);

	return ret;
}

static int get_pci_addr(const char *bdf, opae_pci_addr *addr)
{
	struct rte_pci_addr pci_addr;
	int ret = 0;

	if (!bdf || !addr)
		return -EINVAL;

	ret = rte_pci_addr_parse(bdf, &pci_addr);
	if (ret == 0) {
		addr->domain = pci_addr.domain;
		addr->bus = pci_addr.bus;
		addr->devid = pci_addr.devid;
		addr->function = pci_addr.function;
	}

	return ret;
}

static int check_pcidev_id(pcidev_id id)
{
	if (!id) {
		opae_log_err("ID is NULL\n");
		return -1;
	}

	if (strnlen(id->bdf, PCI_PRI_STR_SIZE) == PCI_PRI_STR_SIZE) {
		opae_log_err("PCI address is too long\n");
		return -2;
	}

	return 0;
}

static int get_rawdev_id(pcidev_id id, uint16_t *dev_id, int log)
{
	if (check_pcidev_id(id))
		return -1;

	if (rte_pmd_ifpga_get_dev_id(id->bdf, dev_id)) {
		if (log)
			opae_log_warn("%s is not probed by ifpga driver\n",
				id->bdf);
		return -1;
	}

	return 0;
}

static struct rte_pci_device *get_rte_pcidev(pcidev_id id, int log)
{
	const struct rte_pci_bus *pci_bus = NULL;
	struct rte_pci_device *pci_dev = NULL;
	struct rte_pci_addr addr;

	if (check_pcidev_id(id))
		return NULL;

	if (rte_pci_addr_parse(id->bdf, &addr)) {
		opae_log_err("PCI address %s is invalid\n", id->bdf);
		return NULL;
	}

	pci_bus = rte_pmd_ifpga_get_pci_bus();
	if (pci_bus) {
		TAILQ_FOREACH(pci_dev, &pci_bus->device_list, next) {
			if (!rte_pci_addr_cmp(&pci_dev->addr, &addr))
				return pci_dev;
		}
	}

	if (log)
		opae_log_err("No rte_pci_device for %s\n", id->bdf);

	return NULL;
}

int opae_load_rsu_status(pcidev_id id, uint32_t *status, uint32_t *progress)
{
	uint16_t dev_id = 0;

	if (!check_eal(1))
		return -EPERM;

	if (get_rawdev_id(id, &dev_id, 1))
		return -ENODEV;

	return rte_pmd_ifpga_get_rsu_status(dev_id, status, progress);
}

int opae_store_rsu_status(pcidev_id id, uint32_t status, uint32_t progress)
{
	uint16_t dev_id = 0;

	if (!check_eal(1))
		return -EPERM;

	if (get_rawdev_id(id, &dev_id, 1))
		return -ENODEV;

	return rte_pmd_ifpga_set_rsu_status(dev_id, status, progress);
}

static int get_pci_property(pcidev_id id, opae_pci_property *prop)
{
	char path[PATH_MAX] = {0};
	int ret = 0;

	if (!id || !prop)
		return -EINVAL;

	snprintf(path, PATH_MAX, "%s/%s", rte_pci_get_sysfs_path(), id->bdf);

	ret = get_pci_id(path, &prop->id);
	if (ret < 0)
		return ret;

	ret = get_pci_addr(id->bdf, &prop->addr);
	if (ret < 0)
		return ret;

	snprintf(prop->pci_addr, OPAE_NAME_SIZE, "%s", id->bdf);
	get_driver(id, prop->drv_name, sizeof(prop->drv_name));

	return 0;
}

static int get_fme_property(rte_pmd_ifpga_common_prop *common,
	opae_fme_property *prop)
{
	opae_bitstream_id bbs_id;

	if (!common || !prop)
		return -EINVAL;

	prop->boot_page = common->boot_page;
	prop->num_ports = common->num_ports;
	prop->bitstream_id = common->bitstream_id;
	prop->bitstream_metadata = common->bitstream_metadata;
	memcpy(prop->pr_id.b, common->pr_id.b, sizeof(opae_uuid));

	bbs_id.id = prop->bitstream_id;
	if (bbs_id.major < sizeof(platform_name) / sizeof(char *)) {
		snprintf(prop->platform_name,
			sizeof(prop->platform_name), "%s",
			platform_name[bbs_id.major]);
	} else {
		snprintf(prop->platform_name,
			sizeof(prop->platform_name), "unknown");
	}

	snprintf(prop->dcp_version, sizeof(prop->dcp_version),
		"DCP 1.%u", bbs_id.minor);

	if (bbs_id.patch < sizeof(release_name)/sizeof(char *)) {
		snprintf(prop->release_name, sizeof(prop->release_name),
			"%s", release_name[bbs_id.patch]);
	} else {
		snprintf(prop->release_name, sizeof(prop->release_name),
			"unknown");
	}

	if (bbs_id.major == 0) {  /* Vista Creek */
		if (bbs_id.interface <
			sizeof(interface_type) / sizeof(char *)) {
			snprintf(prop->interface_type,
				sizeof(prop->interface_type), "%s",
				interface_type[bbs_id.interface]);
		} else {
			snprintf(prop->interface_type,
				sizeof(prop->interface_type), "unknown");
		}
	} else {
		snprintf(prop->interface_type,
			sizeof(prop->interface_type), "unknown");
	}

	snprintf(prop->build_version, sizeof(prop->build_version),
		"%u.%u.%u", bbs_id.build_major, bbs_id.build_minor,
		bbs_id.build_patch);

	return 0;
}

static int get_port_property(rte_pmd_ifpga_port_prop *port,
	opae_port_property *prop)
{
	if (!port || !prop)
		return -EINVAL;

	memcpy(prop->afu_id.b, port->afu_id.b, sizeof(opae_uuid));
	prop->type = port->type;

	return 0;
}

static int get_bmc_property(rte_pmd_ifpga_common_prop *common,
	opae_bmc_property *prop)
{
	opae_bmc_version ver;

	if (!common || !prop)
		return -EINVAL;

	ver.version = common->bmc_version;
	snprintf(prop->bmc_version, sizeof(prop->bmc_version), "%c.%u.%u.%u",
		ver.board, ver.major, ver.minor, ver.micro);

	ver.version = common->bmc_nios_version;
	snprintf(prop->fw_version, sizeof(prop->fw_version), "%c.%u.%u.%u",
		ver.board, ver.major, ver.minor, ver.micro);

	return 0;
}

int opae_get_property(pcidev_id id, opae_fpga_property *prop, int type)
{
	uint16_t dev_id = 0;
	uint32_t i = 0;
	rte_pmd_ifpga_prop fpga_prop;
	int ret = 0;

	if (!prop) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	if (type == 0)
		type = OPAE_PROP_ALL;

	memset(prop, 0, sizeof(opae_fpga_property));

	/* PCI properties */
	if (type & OPAE_PROP_PCI) {
		if (get_pci_property(id, &prop->pci) < 0) {
			opae_log_err("Failed to get PCI property\n");
			return -EAGAIN;
		}
	}

	if (type == OPAE_PROP_PCI)
		return 0;

	if (!check_eal(1))
		return -EPERM;

	if (get_rawdev_id(id, &dev_id, 1))
		return -ENODEV;

	ret = rte_pmd_ifpga_get_property(dev_id, &fpga_prop);
	if (ret) {
		opae_log_err("Failed to get FPGA property [e:%d]\n", ret);
		return -EAGAIN;
	}

	/* FME properties */
	if (type & (OPAE_PROP_FME | OPAE_PROP_PORT))
		get_fme_property(&fpga_prop.common, &prop->fme);

	/* PORT properties */
	if (type & OPAE_PROP_PORT) {
		for (i = 0; i < prop->fme.num_ports; i++) {
			prop->port[i].index = i;
			get_port_property(&fpga_prop.port[i], &prop->port[i]);
		}
	}

	/* BMC properties */
	if (type & OPAE_PROP_BMC)
		get_bmc_property(&fpga_prop.common, &prop->bmc);

	return 0;
}

int opae_get_phy_info(pcidev_id id, opae_phy_info *info)
{
	uint16_t dev_id = 0;
	rte_pmd_ifpga_phy_info phy_info;
	int ret = 0;

	if (!info)
		return -EINVAL;

	if (get_rawdev_id(id, &dev_id, 1))
		return -ENODEV;

	ret = rte_pmd_ifpga_get_phy_info(dev_id, &phy_info);
	if (ret) {
		opae_log_err("Failed to get PHY information [e:%d]\n", ret);
		return -EAGAIN;
	}

	info->num_retimers = phy_info.num_retimers;
	info->link_speed = phy_info.link_speed;
	info->link_status = phy_info.link_status;

	return 0;
}

static int update_driver(pcidev_id id, char *drv_name)
{
	struct rte_pci_device *pci_dev = NULL;
	char name[OPAE_NAME_SIZE] = {0};
	int ret = 0;

	if (check_pcidev_id(id))
		return -EINVAL;

	if (drv_name) {
		if (strlen(drv_name) >= OPAE_NAME_SIZE) {
			opae_log_err("Driver name \'%s\' too long\n",
				drv_name);
			return -EINVAL;
		}
		strncpy(name, drv_name, sizeof(name));
	} else {
		ret = get_driver(id, name, sizeof(name));
		if (ret < 0)
			return ret;
	}

	pci_dev = get_rte_pcidev(id, 0);
	if (pci_dev) {
		if (strlen(name) == 0) {
			pci_dev->kdrv = RTE_PCI_KDRV_NONE;
		} else {
			if (!strcmp(name, OPAE_KDRV_VFIO_PCI))
				pci_dev->kdrv = RTE_PCI_KDRV_VFIO;
			else if (!strcmp(name, OPAE_KDRV_IGB_UIO))
				pci_dev->kdrv = RTE_PCI_KDRV_IGB_UIO;
			else if (!strcmp(name, OPAE_KDRV_UIO_PCI))
				pci_dev->kdrv = RTE_PCI_KDRV_UIO_GENERIC;
			else
				pci_dev->kdrv = RTE_PCI_KDRV_UNKNOWN;
		}
	}

	return 0;
}

int opae_unbind_driver(pcidev_id id)
{
	uint16_t dev_id = 0;
	char path[PATH_MAX] = {0};
	char drv_name[OPAE_NAME_SIZE] = {0};
	char null[] = {0};
	int ret = 0;

	if (!get_rawdev_id(id, &dev_id, 0)) {
		opae_log_err("%s is probed, remove it first\n", id->bdf);
		return -EBUSY;
	}

	ret = get_driver(id, drv_name, sizeof(drv_name));
	if (ret < 0)
		return ret;

	if (strlen(drv_name) > 0) {
		snprintf(path, PATH_MAX, "/sys/bus/pci/drivers/%s/unbind",
			drv_name);
		ret = write_file(path, id->bdf, strlen(id->bdf) + 1);
		if (ret == 0)
			ret = update_driver(id, null);
	}

	return ret;
}

static int check_driver(const char *drv_name)
{
	char path[PATH_MAX] = {0};
	struct stat buf;

	if (!drv_name)
		return -EINVAL;

	if (strlen(drv_name) > 0) {
		snprintf(path, PATH_MAX, "/sys/bus/pci/drivers/%s", drv_name);
		if ((stat(path, &buf) < 0) || ((buf.st_mode & S_IFDIR) == 0)) {
			opae_log_warn("Driver %s is not installed\n",
				drv_name);
			return -EINVAL;
		}
	}

	return 0;
}

int opae_bind_driver(pcidev_id id, char *drv_name)
{
	char path[PATH_MAX] = {0};
	char name[OPAE_NAME_SIZE] = {0};
	char null[] = {0};
	int ret = 0;

	ret = check_driver(drv_name);
	if (ret < 0)
		return ret;

	ret = get_driver(id, name, sizeof(name));
	if (ret < 0)
		return ret;

	if (!strcmp(drv_name, name))   /* driver not change */
		return 0;

	ret = opae_unbind_driver(id);
	if (ret < 0)
		return ret;

	if (strlen(drv_name) > 0) {
		/* bind driver */
		snprintf(path, PATH_MAX, "%s/%s/driver_override",
			rte_pci_get_sysfs_path(), id->bdf);
		ret = write_file(path, drv_name, strlen(drv_name) + 1);
		if (ret < 0)
			goto update_drv;

		snprintf(path, PATH_MAX, "/sys/bus/pci/drivers/%s/bind",
			drv_name);
		ret = write_file(path, id->bdf, strlen(id->bdf) + 1);
		if (ret < 0)
			goto update_drv;

		snprintf(path, PATH_MAX, "%s/%s/driver_override",
			rte_pci_get_sysfs_path(), id->bdf);
		ret = write_file(path, null, 1);
		if (ret < 0)
			goto update_drv;
	}

update_drv:
	ret = update_driver(id, NULL);
	if (ret < 0)
		opae_log_err("Failed to update driver information of %s\n",
			id->bdf);

	return 0;
}

int opae_probe_device(pcidev_id id)
{
	const struct rte_pci_bus *pci_bus = NULL;
	struct rte_pci_device *pci_dev = NULL;

	if (check_pcidev_id(id))
		return -EINVAL;

	if (!check_eal(1))
		return -EPERM;

	/* make sure device is added in rte_pci_bus devices list */
	pci_bus = rte_pmd_ifpga_get_pci_bus();
	if (pci_bus && pci_bus->bus.scan)
		pci_bus->bus.scan();

	pci_dev = get_rte_pcidev(id, 1);
	if (!pci_dev)
		return -ENODEV;

	if (pci_dev->kdrv != RTE_PCI_KDRV_VFIO) {
		opae_log_err("vfio-pci driver is not bound to %s\n", id->bdf);
		return -EINVAL;
	}

	if (!pci_bus || !pci_bus->bus.plug)
		return -ENODEV;

	return pci_bus->bus.plug(&pci_dev->device);
}

int opae_remove_device(pcidev_id id)
{
	struct rte_pci_device *pci_dev = NULL;
	struct rte_pci_driver *pci_drv = NULL;
	int ret = 0;

	if (!check_eal(1))
		return -EPERM;

	pci_dev = get_rte_pcidev(id, 0);
	if (pci_dev && pci_dev->driver) {
		pci_drv = pci_dev->driver;
		ret = pci_drv->remove(pci_dev);
		if (ret < 0) {
			opae_log_err("Failed to remove %s [e:%d]\n",
				id->bdf, ret);
			return ret;
		}
		pci_dev->driver = NULL;
		pci_dev->device.driver = NULL;
		if (pci_drv->drv_flags & RTE_PCI_DRV_NEED_MAPPING)
			rte_pci_unmap_device(pci_dev);
	}

	return ret;
}

static int is_pac(pcidev_id id)
{
	char path[PATH_MAX] = {0};
	opae_pci_id pci_id;

	if (check_pcidev_id(id))
		return 0;

	snprintf(path, PATH_MAX, "%s/%s", rte_pci_get_sysfs_path(), id->bdf);
	if (get_pci_id(path, &pci_id) < 0)
		return 0;

	if ((pci_id.vendor_id == 0x8086) && (pci_id.device_id == 0x0b30))
		return 1;

	return 0;
}

int opae_get_parent(pcidev_id id, pcidev_id parent)
{
	char path[PATH_MAX] = {0};
	char link[PATH_MAX] = {0};
	int ret = 0;

	if (!id || !parent) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		ret = -EINVAL;
		goto end;
	}

	snprintf(path, PATH_MAX, "%s/%s", rte_pci_get_sysfs_path(), id->bdf);
	ret = readlink(path, link, PATH_MAX);
	if (ret >= PATH_MAX) {
		opae_log_err("Length of link path exceeds %u\n", PATH_MAX);
		ret = -ENAMETOOLONG;
		goto end;
	}

	if (ret > 0) {
		ret = extract_path(link, 1, parent->bdf, sizeof(parent->bdf));
		if (!strncmp(parent->bdf, "pci", 3)) {
			parent->bdf[0] = 0;
			ret = -ENODEV;
		}
	} else {
		parent->bdf[0] = 0;
		if (ret == 0)
			opae_log_err("Length of link path is 0\n");
		else
			opae_log_err("No link path for \'%s\'\n", path);
	}
end:
	if (ret <= 0)
		opae_log_err("%s has no parent\n", id->bdf);

	return ret;
}

int opae_get_child(pcidev_id id, pcidev_id child, int size)
{
	glob_t pglob = {.gl_pathc = 0, .gl_pathv = NULL};
	char path[PATH_MAX] = {0};
	int i, count = 0;
	int len = 0;
	int ret = 0;

	if (!id || (size < 0)) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	snprintf(path, PATH_MAX, "%s/%s/*:*:*.?", rte_pci_get_sysfs_path(),
		id->bdf);
	ret = glob(path, 0, NULL, &pglob);
	if (ret == 0) {
		if (child && (size > 0)) {
			for (i = 0; i < (int)pglob.gl_pathc; i++) {
				len = extract_path(pglob.gl_pathv[i], 0,
					child->bdf, sizeof(child->bdf));
				if (len <= 0) {
					child->bdf[0] = 0;
					continue;
				}
				if (++count >= size)
					break;
				child++;
			}
		} else {
			count = (int)pglob.gl_pathc;
		}
		globfree(&pglob);
	} else {
		if (pglob.gl_pathv)
			globfree(&pglob);
	}

	return count;
}

int opae_get_pf1(pcidev_id id, pcidev_id peer, int size)
{
	opae_pci_device parent;
	opae_pci_device child[4];
	int n = 0;
	int ret = 0;

	if (check_pcidev_id(id))
		return -EINVAL;

	if (!is_pac(id)) {
		opae_log_info("%s has no peer function\n", id->bdf);
		return -EINVAL;
	}

	ret = opae_get_parent(id, &parent);
	if (ret < 0)
		return -ENODEV;
	ret = opae_get_parent(&parent, &parent);
	if (ret < 0)
		return -ENODEV;

	n = opae_get_child(&parent, child,
		sizeof(child) / sizeof(opae_pci_device));
	/* there should have four downstream ports of PCI switch on board */
	if (n == 4) {
		n = opae_get_child(&child[3], peer, size);
	} else {
		peer->bdf[0] = 0;
		opae_log_dbg("%s has %d child(s)\n", parent.bdf, n);
		n = 0;
	}

	return n;
}

int opae_update_flash(pcidev_id id, const char *image, uint64_t *status)
{
	opae_img_info info;
	uint16_t dev_id = 0;
	int ret = 0;

	ret = opae_get_image_info(image, &info);
	if (ret < 0) {
		opae_log_err("Failed to get image information [e:%d]\n", ret);
		return -EINVAL;
	}

	if ((info.type != OPAE_IMG_TYPE_BBS) &&
		(info.type != OPAE_IMG_TYPE_BMC)) {
		opae_log_err("Image is not supported [t:%u]\n", info.type);
		return -EOPNOTSUPP;
	}

	if (!check_eal(1))
		return -EPERM;

	if (get_rawdev_id(id, &dev_id, 1))
		return -ENODEV;

	return rte_pmd_ifpga_update_flash(dev_id, image, status);
}

int opae_cancel_flash_update(pcidev_id id, int force)
{
	uint16_t dev_id = 0;

	if (!check_eal(1))
		return -EPERM;

	if (get_rawdev_id(id, &dev_id, 1))
		return -ENODEV;

	return rte_pmd_ifpga_stop_update(dev_id, force);
}

static int find_pci_ecap(int fd, unsigned int cap)
{
	uint32_t header = 0;
	int ttl = (RTE_PCI_CFG_SPACE_EXP_SIZE - RTE_PCI_CFG_SPACE_SIZE) / 8;
	int pos = RTE_PCI_CFG_SPACE_SIZE;
	int ret = 0;

	ret = pread(fd, &header, sizeof(header), pos);
	if (ret < 0) {
		opae_log_err("Failed to read from PCI configuration space [e:%s]\n",
			strerror(errno));
		return ret;
	}
	opae_log_dbg("Read 0x%08x from PCI configuration space 0x%x\n",
		header, pos);

	if (header == 0) {
		opae_log_err("Capability is empty\n");
		return 0;
	}

	while (ttl-- > 0) {
		if ((RTE_PCI_EXT_CAP_ID(header) == cap) && (pos != 0))
			return pos;

		pos = RTE_PCI_EXT_CAP_NEXT(header);
		if (pos < RTE_PCI_CFG_SPACE_SIZE) {
			opae_log_err("Position of capability is invalid"
						 "[e:%d]\n", pos);
			break;
		}
		ret = pread(fd, &header, sizeof(header), pos);
		if (ret < 0) {
			opae_log_err("Failed to read from PCI config space [e:%s]\n",
				strerror(errno));
			return ret;
		}
		opae_log_dbg("Read 0x%08x from PCI configuration space 0x%x\n",
			header, pos);
	}

	return 0;
}

static int set_aer(pcidev_id id, uint32_t v1, uint32_t v2, int record)
{
	char path[PATH_MAX] = {0};
	uint32_t val = 0;
	int fd = -1;
	int pos = 0;
	int ret = 0;

	if (!id)
		return -EINVAL;

	snprintf(path, PATH_MAX, "%s/%s/config",
		rte_pci_get_sysfs_path(), id->bdf);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		opae_log_err("Failed to open \'%s\' for RDWR [e:%s]\n",
			path, strerror(errno));
		return -EIO;
	}

	pos = find_pci_ecap(fd, RTE_PCI_EXT_CAP_ID_ERR);
	if (pos <= 0) {
		opae_log_warn("AER capability is not present\n");
		ret = -ENXIO;
		goto close_fd;
	}

	if (record) {
		ret = pread(fd, &val, sizeof(val), pos + 0x08);
		if (ret < 0) {
			opae_log_err("Failed to read from PCI config space [e:%s]\n",
				strerror(errno));
			goto close_fd;
		}
		opae_log_dbg("Read 0x%08x from PCI configuration space 0x%x\n",
			val, pos + 0x08);
		dev_aer[0] = val;

		ret = pread(fd, &val, sizeof(val), pos + 0x14);
		if (ret < 0) {
			opae_log_err("Failed to read from PCI config space [e:%s]\n",
				strerror(errno));
			goto close_fd;
		}
		opae_log_dbg("Read 0x%08x from PCI configuration space 0x%x\n",
			val, pos + 0x14);
		dev_aer[1] = val;
	}

	opae_log_dbg("Write 0x%08x to PCI configuration space 0x%x\n",
		v1, pos + 0x08);
	ret = pwrite(fd, &v1, sizeof(v1), pos + 0x08);
	if (ret < 0) {
		opae_log_err("Failed to write to PCI config space 0x%x [e:%s]\n",
			pos + 0x08, strerror(errno));
		goto close_fd;
	}

	opae_log_dbg("Write 0x%08x to PCI configuration space 0x%x\n",
		v2, pos + 0x14);
	ret = pwrite(fd, &v2, sizeof(v2), pos + 0x14);
	if (ret < 0) {
		opae_log_err("Failed to write to PCI config space 0x%x [e:%s]\n",
			pos + 0x14, strerror(errno));
	}

close_fd:
	close(fd);
	return ret < 0 ? ret : 0;
}

static int enable_aer(pcidev_id id)
{
	if (check_pcidev_id(id))
		return -EINVAL;

	opae_log_info("Enable AER of %s\n", id->bdf);

	return set_aer(id, dev_aer[0], dev_aer[1], 0);
}

static int disable_aer(pcidev_id id)
{
	if (check_pcidev_id(id))
		return -EINVAL;

	opae_log_info("Disable AER of %s\n", id->bdf);

	return set_aer(id, 0xffffffff, 0xffffffff, 1);
}

static int remove_tree(pcidev_id id)
{
	int i, n = 0;
	pcidev_id child;
	int ret = 0;

	if (check_pcidev_id(id))
		return -EINVAL;

	n = opae_get_child(id, NULL, 0);
	if (n > 0) {
		child = (pcidev_id)rte_zmalloc(NULL,
			sizeof(opae_pci_device) * n, 0);
		if (!child) {
			opae_log_err("Failed to malloc for children of %s\n",
				id->bdf);
			ret = -ENOMEM;
			goto end;
		}

		opae_get_child(id, child, n);
		for (i = 0; i < n; i++)
			remove_tree(&child[i]);
		rte_free(child);
	}

end:
	opae_remove_device(id);
	return ret;
}

static int remove_device(pcidev_id id)
{
	char path[PATH_MAX] = {0};
	char one[] = {'1', 0};
	int ret = 0;

	if (check_pcidev_id(id))
		return -EINVAL;

	opae_log_info("Remove %s from system\n", id->bdf);

	snprintf(path, PATH_MAX, "%s/%s/remove",
		rte_pci_get_sysfs_path(), id->bdf);
	ret = write_file(path, one, strlen(one));
	if (ret < 0) {
		opae_log_err("Failed to remove %s from system\n", id->bdf);
		return ret;
	}

	remove_tree(id);

	return 0;
}

static int scan_device(pcidev_id parent, pcidev_id id)
{
	char path[PATH_MAX] = {0};
	char bus[8] = {0};
	char one[] = {'1', 0};
	char pwr[16] = {0};
	char pwr_on[] = {'o', 'n', 0};
	int pwr_on_failed = 0;
	int ret = 0;

	if (!parent) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}
	opae_log_info("Rescan devices under %s\n", parent->bdf);

	if (id) {   /* scan specified bus under parent device */
		snprintf(path, PATH_MAX, "%s/%s/power/control",
			rte_pci_get_sysfs_path(), parent->bdf);
		ret = read_file(path, pwr, sizeof(pwr));
		if (ret < 0)
			return ret;

		if (strcmp(pwr, "on")) {
			ret = write_file(path, pwr_on, strlen(pwr_on));
			if (ret < 0)
				pwr_on_failed = 1;
			else
				sleep(1);
		}

		snprintf(bus, sizeof(bus), "%s", id->bdf);
		snprintf(path, PATH_MAX, "%s/%s/pci_bus/%s/rescan",
			rte_pci_get_sysfs_path(), parent->bdf, bus);
		ret = write_file(path, one, strlen(one));
		if (ret < 0)
			return ret;

		if (pwr_on_failed) {   /* workaround for power on failed */
			ret = write_file(path, one, strlen(one));
			if (ret < 0)
				return ret;
		}

		if (strcmp(pwr, "on")) {
			snprintf(path, PATH_MAX, "%s/%s/power/control",
				rte_pci_get_sysfs_path(), parent->bdf);
			ret = write_file(path, pwr, strlen(pwr));
		}
	} else {   /* scan all buses under parent device */
		snprintf(path, PATH_MAX, "%s/%s/rescan",
			rte_pci_get_sysfs_path(), parent->bdf);
		ret = write_file(path, one, strlen(one));
	}

	return ret;
}

int opae_reboot_device(pcidev_id id, int type, int page)
{
	uint16_t dev_id = 0;
	opae_pci_device fpga;    /* FPGA after reboot */
	opae_pci_device parent;
	opae_pci_device peer[2];   /* physical function 1 of FPGA */
	opae_pci_device peer_parent;
	opae_pci_device ups;   /* upstream port device */
	opae_pci_device root;  /* port connected to PAC */
	pcidev_id peer_primary = NULL;
	char drv_name[OPAE_NAME_SIZE] = {0};
	int n = 0;
	int i = 0;
	int ret = 0;

	if (check_pcidev_id(id))
		return -EINVAL;

	if (!is_pac(id)) {
		opae_log_err("%s can not be rebooted\n", id->bdf);
		return -EINVAL;
	}

	if (get_rawdev_id(id, &dev_id, 1))
		return -ENODEV;

	ret = opae_get_parent(id, &parent);
	if (ret < 0)
		return -ENODEV;
	ret = opae_get_parent(&parent, &ups);
	if (ret < 0)
		return -ENODEV;
	ret = opae_get_parent(&ups, &root);
	if (ret < 0)
		return -ENODEV;

	n = opae_get_pf1(id, peer, sizeof(peer) / sizeof(opae_pci_device));
	if (n <= 0) {
		opae_log_err("PF1 of %s is not found\n", id->bdf);
	} else {
		peer_primary = &peer[0];
		ret = opae_get_parent(peer_primary, &peer_parent);
		if (ret < 0)
			return -ENODEV;
	}

	get_driver(id, drv_name, sizeof(drv_name));  /* save original driver */

	if (!check_eal(1))
		return -EPERM;

	if (rte_pmd_ifpga_reboot_try(dev_id)) {
		opae_log_warn("Update or reboot is in progress\n");
		return -EAGAIN;
	}

	if (type == 0) {
		/* disable AER */
		ret = disable_aer(&parent);
		if (ret < 0) {
			opae_log_err("Failed to disable AER of %s\n",
				parent.bdf);
			goto reboot_end;
		}
		ret = disable_aer(&peer_parent);
		if (ret < 0) {
			opae_log_err("Failed to disable AER of %s\n",
				peer_parent.bdf);
			goto reboot_end;
		}

		/* trigger reconfiguration */
		ret = rte_pmd_ifpga_reload(dev_id, type, page);
		if (ret == 0) {
			ret = remove_device(id);
			for (i = 0; i < n; i++)
				ret += remove_device(&peer[i]);
			if (ret == 0) {
				opae_log_info("Wait 10 seconds for FPGA reloading\n");
				sleep(10);
				ret = scan_device(&parent, id);
				if (ret < 0)
					opae_log_err("Failed to rescan %s\n",
						id->bdf);
				if (peer_primary) {
					ret = scan_device(&peer_parent,
						peer_primary);
					if (ret < 0) {
						opae_log_err("Failed to rescan %s\n",
							peer_primary->bdf);
					}
				}
			}
		}

		/* restore AER */
		if (enable_aer(&parent) < 0) {
			opae_log_err("Failed to enable AER of %s\n",
				parent.bdf);
		}
		if (enable_aer(&peer_parent) < 0) {
			opae_log_err("Failed to enable AER of %s\n",
				peer_parent.bdf);
		}
	} else if (type == 1) {
		/* disable AER */
		ret = disable_aer(&root);
		if (ret < 0) {
			opae_log_err("Failed to disable AER of %s\n", root.bdf);
			goto reboot_end;
		}

		/* trigger reconfiguration */
		ret = rte_pmd_ifpga_reload(dev_id, type, page);
		if (ret == 0) {
			ret += remove_device(&ups);
			if (ret == 0) {
				opae_log_info("Wait 10 seconds for BMC reloading\n");
				sleep(10);
				ret = scan_device(&root, &ups);
				if (ret < 0)
					opae_log_err("Failed to rescan %s\n",
						ups.bdf);
			}
		}

		/* restore AER */
		if (enable_aer(&root) < 0)
			opae_log_err("Failed to enable AER of %s\n", root.bdf);
	} else {
		opae_log_err("Type of reboot is not supported [t:%d]\n", type);
		ret = -EINVAL;
		goto reboot_end;
	}

	/* update id if bdf changed after reboot */
	if (opae_get_child(&parent, &fpga, 1) == 1) {
		if (strcmp(id->bdf, fpga.bdf))
			id = &fpga;
	}

	ret = opae_bind_driver(id, drv_name);
	if (ret < 0)
		opae_log_err("Failed to bind original driver of %s\n", id->bdf);

	ret = opae_probe_device(id);
	if (ret < 0)
		opae_log_err("Failed to probe %s [e:%d]\n", id->bdf, ret);

reboot_end:
	rte_pmd_ifpga_set_rsu_status(dev_id, 0, 0);
	return ret;
}

int opae_partial_reconfigure(pcidev_id id, int port, const char *gbs)
{
	uint16_t dev_id = 0;

	if (!id || !gbs) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	if (!check_eal(1))
		return -EPERM;

	if (get_rawdev_id(id, &dev_id, 1))
		return -ENODEV;

	return rte_pmd_ifpga_partial_reconfigure(dev_id, port, gbs);
}

int opae_read_pci_cfg(pcidev_id id, uint32_t address, uint32_t *value)
{
	char path[PATH_MAX] = {0};
	int fd = -1;
	int ret = 0;

	if (!id || !value) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	snprintf(path, PATH_MAX, "%s/%s/config", rte_pci_get_sysfs_path(),
		id->bdf);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		opae_log_dbg("Failed to open \'%s\' for RDONLY [e:%s]\n",
			path, strerror(errno));
		return -EIO;
	}

	ret = pread(fd, value, 4, address);
	if (ret < 0) {
		opae_log_err("Failed to read from PCI device %s [e:%s]\n",
			id->bdf, strerror(errno));
		close(fd);
		return ret;
	}

	opae_log_dbg("CONFIG+0x%08x -> 0x%08x\n", address, *value);
	close(fd);
	return 0;
}

int opae_write_pci_cfg(pcidev_id id, uint32_t address, uint32_t value)
{
	char path[PATH_MAX] = {0};
	int fd = -1;
	int ret = 0;

	if (!id) {
		opae_log_err("Input parameter of %s is invalid\n", __func__);
		return -EINVAL;
	}

	snprintf(path, PATH_MAX, "%s/%s/config", rte_pci_get_sysfs_path(),
		id->bdf);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		opae_log_dbg("Failed to open \'%s\' for WRONLY [e:%s]\n",
			path, strerror(errno));
		return -EIO;
	}

	ret = pwrite(fd, &value, 4, address);
	if (ret < 0) {
		opae_log_err("Failed to write to PCI device %s [e:%s]\n",
			id->bdf, strerror(errno));
		close(fd);
		return ret;
	}

	opae_log_dbg("CONFIG+0x%08x <- 0x%08x\n", address, value);
	close(fd);
	return 0;
}
