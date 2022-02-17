/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018, Microsoft Corporation.
 * All Rights Reserved.
 */

#include <rte_eal.h>
#include <rte_bus_vmbus.h>

#include "private.h"

#include <sys/bus.h>
#include <sys/types.h>
#include <sys/sysctl.h>

/*
 * GUID associated with network devices
 * {f8615163-df3e-46c5-913f-f2d2f965ed0e}
 */
static const rte_uuid_t vmbus_nic_uuid = {
	0xf8, 0x61, 0x51, 0x63,
	0xdf, 0x3e,
	0x46, 0xc5,
	0x91, 0x3f,
	0xf2, 0xd2, 0xf9, 0x65, 0xed, 0xe
};

extern struct rte_vmbus_bus rte_vmbus_bus;

/* Parse UUID. Caller must pass NULL terminated string */
static int
parse_sysfs_uuid(const char *filename, rte_uuid_t uu)
{
	char in[BUFSIZ];

	memcpy(in, filename, BUFSIZ);
	if (rte_uuid_parse(in, uu) < 0) {
		VMBUS_LOG(ERR, "%s not a valid UUID", in);
		return -1;
	}

	return 0;
}

/* Scan one vmbus entry, and fill the devices list from it. */
static int
vmbus_scan_one(const char *name, unsigned int unit_num)
{
	struct rte_vmbus_device *dev, *dev2;
	char sysctlBuffer[PATH_MAX], sysctlVar[PATH_MAX];
	size_t guid_len = 36, len = PATH_MAX;
	char classid[guid_len + 1], deviceid[guid_len + 1];

	dev = calloc(1, sizeof(*dev));
	if (dev == NULL)
		return -1;

	/* get class id and device id */
	snprintf(sysctlVar, len, "dev.%s.%u.%%pnpinfo", name, unit_num);
	if (sysctlbyname(sysctlVar, &sysctlBuffer, &len, NULL, 0) < 0)
		goto error;

	/* pnpinfo: classid=f912ad6d-2b17-48ea-bd65-f927a61c7684
	 * deviceid=d34b2567-b9b6-42b9-8778-0a4ec0b955bf
	 */
	if (sysctlBuffer[0] == 'c' && sysctlBuffer[1] == 'l' &&
	    sysctlBuffer[7] == '=') {
		memcpy(classid, &sysctlBuffer[8], guid_len);
		classid[guid_len] = '\0';
	}
	if (parse_sysfs_uuid(classid, dev->class_id) < 0)
		goto error;

	/* skip non-network devices */
	if (rte_uuid_compare(dev->class_id, vmbus_nic_uuid) != 0) {
		free(dev);
		return 0;
	}

	if (sysctlBuffer[45] == 'd' && sysctlBuffer[46] == 'e' &&
	    sysctlBuffer[47] == 'v' && sysctlBuffer[53] == '=') {
		memcpy(deviceid, &sysctlBuffer[54], guid_len);
		deviceid[guid_len] = '\0';
	}
	if (parse_sysfs_uuid(deviceid, dev->device_id) < 0)
		goto error;

	if (!strcmp(name, "hv_uio"))
		dev->uio_num = unit_num;
	else
		dev->uio_num = -1;
	dev->device.bus = &rte_vmbus_bus.bus;
	dev->device.numa_node = 0;
	dev->device.name = strdup(deviceid);
	if (!dev->device.name)
		goto error;

	dev->device.devargs = vmbus_devargs_lookup(dev);

	/* device is valid, add in list (sorted) */
	VMBUS_LOG(DEBUG, "Adding vmbus device %s", name);

	TAILQ_FOREACH(dev2, &rte_vmbus_bus.device_list, next) {
		int ret;

		ret = rte_uuid_compare(dev->device_id, dev2->device_id);
		if (ret > 0)
			continue;

		if (ret < 0) {
			vmbus_insert_device(dev2, dev);
		} else { /* already registered */
			VMBUS_LOG(NOTICE,
				"%s already registered", name);
			free(dev);
		}
		return 0;
	}

	vmbus_add_device(dev);
	return 0;
error:
	VMBUS_LOG(DEBUG, "failed");

	free(dev);
	return -1;
}

/*
 * Scan the content of the vmbus, and the devices in the devices list
 */
int
rte_vmbus_scan(void)
{
	struct u_device udev;
	struct u_businfo ubus;
	int dev_idx, dev_ptr, name2oid[2], oid[CTL_MAXNAME + 12], error;
	size_t oidlen, rlen, ub_size;
	uintptr_t vmbus_handle = 0;
	char *walker, *ep;
	char name[16] = "hw.bus.devices";
	char *dd_name, *dd_desc, *dd_drivername, *dd_pnpinfo, *dd_location;

	/*
	 * devinfo FreeBSD APP logic to fetch all the VMBus devices
	 * using SYSCTLs
	 */
	name2oid[0] = 0;
	name2oid[1] = 3;
	oidlen = sizeof(oid);
	error = sysctl(name2oid, 2, oid, &oidlen, name, strlen(name));
	if (error < 0) {
		VMBUS_LOG(DEBUG, "can't find hw.bus.devices sysctl node");
		return -ENOENT;
	}
	oidlen /= sizeof(int);
	if (oidlen > CTL_MAXNAME) {
		VMBUS_LOG(DEBUG, "hw.bus.devices oid is too large");
		return -EINVAL;
	}

	ub_size = sizeof(ubus);
	if (sysctlbyname("hw.bus.info", &ubus, &ub_size, NULL, 0) != 0) {
		VMBUS_LOG(DEBUG, "sysctlbyname(\"hw.bus.info\", ...) failed");
		return -EINVAL;
	}
	if ((ub_size != sizeof(ubus)) ||
	    (ubus.ub_version != BUS_USER_VERSION)) {
		VMBUS_LOG(DEBUG,
			"kernel bus interface version mismatch: kernel %d expected %d",
			ubus.ub_version, BUS_USER_VERSION);
		return -EINVAL;
	}

	oid[oidlen++] = ubus.ub_generation;
	dev_ptr = oidlen++;

	/*
	 * Scan devices.
	 *
	 * Stop after a fairly insane number to avoid death in the case
	 * of kernel corruption.
	 */

	for (dev_idx = 0; dev_idx < 10000; dev_idx++) {
		/*
		 * Get the device information.
		 */
		oid[dev_ptr] = dev_idx;
		rlen = sizeof(udev);
		error = sysctl(oid, oidlen, &udev, &rlen, NULL, 0);
		if (error < 0) {
			if (errno == ENOENT)    /* end of list */
				break;
			if (errno != EINVAL)    /* gen count skip, restart */
				VMBUS_LOG(DEBUG, "sysctl hw.bus.devices.%d",
					dev_idx);
			return errno;
		}
		if (rlen != sizeof(udev)) {
			VMBUS_LOG(DEBUG,
				"sysctl returned wrong data %zd bytes instead of %zd",
				rlen, sizeof(udev));
			return -EINVAL;
		}

		walker = udev.dv_fields;
		ep = walker + sizeof(udev.dv_fields);
		dd_name = NULL;
		dd_desc = NULL;
		dd_drivername = NULL;
		dd_pnpinfo = NULL;
		dd_location = NULL;
#define UNPACK(x)						 \
	do {							 \
		x = strdup(walker);				 \
		if (x == NULL)					 \
			return -ENOMEM;				 \
		if (walker + strnlen(walker, ep - walker) >= ep) \
			return -EINVAL;				 \
		walker += strlen(walker) + 1;			 \
	} while (0)

		UNPACK(dd_name);
		UNPACK(dd_desc);
		UNPACK(dd_drivername);
		UNPACK(dd_pnpinfo);
		UNPACK(dd_location);
#undef UNPACK
		if (*dd_drivername && !(strcmp(dd_drivername, "vmbus")))
			vmbus_handle = udev.dv_handle;

		if (vmbus_handle && (vmbus_handle == udev.dv_parent)
		    && *dd_pnpinfo && *dd_name) {
			unsigned int driver_len = 0, unit_num = 0;
			char *endptr;

			driver_len = strlen(dd_drivername);
			unit_num = strtoull(&dd_name[driver_len], &endptr, 10);
			VMBUS_LOG(DEBUG, "Device name:%s, pnpinfo:%s",
				dd_name, dd_pnpinfo);

			if (vmbus_scan_one(dd_drivername, unit_num) < 0)
				goto error;
		}
	}
	return 0;
error:
	return -1;
}
