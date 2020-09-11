/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#include <rte_windows.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_eal_memconfig.h>
#include <rte_eal.h>

#include "private.h"

#include <devpkey.h>

#ifdef RTE_TOOLCHAIN_GCC
#include <devpropdef.h>
DEFINE_DEVPROPKEY(DEVPKEY_Device_Numa_Node, 0x540b947e, 0x8b40, 0x45bc,
	0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2, 3);
#endif

/* GUID definition for device class netUIO */
DEFINE_GUID(GUID_DEVCLASS_NETUIO, 0x78912bc1, 0xcb8e, 0x4b28,
	0xa3, 0x29, 0xf3, 0x22, 0xeb, 0xad, 0xbe, 0x0f);

/* GUID definition for the netuio device interface */
DEFINE_GUID(GUID_DEVINTERFACE_NETUIO, 0x08336f60, 0x0679, 0x4c6c,
	0x85, 0xd2, 0xae, 0x7c, 0xed, 0x65, 0xff, 0xf7);

/* IOCTL code definitions */
#define IOCTL_NETUIO_MAP_HW_INTO_USERMODE \
	CTL_CODE(FILE_DEVICE_NETWORK, 51, METHOD_BUFFERED, \
	    FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define  MAX_DEVICENAME_SZ 255

static const char netuio_class[] = "netuio class";
static const char net_class[] = "net class";

#pragma pack(push)
#pragma pack(8)
struct mem_region {
	UINT64 size;  /* memory region size */
	LARGE_INTEGER phys_addr;  /* physical address of the memory region */
	PVOID virt_addr;  /* virtual address of the memory region */
	PVOID user_mapped_virt_addr;  /* virtual address of the region mapped */
					/* into user process context */
};

#define PCI_MAX_BAR 6

struct device_info {
	struct mem_region hw[PCI_MAX_BAR];
	USHORT reserved;
};
#pragma pack(pop)

/*
 * This code is used to simulate a PCI probe by parsing information in
 * the registry hive for PCI devices.
 */

/* The functions below are not implemented on Windows,
 * but need to be defined for compilation purposes
 */

/* Map pci device */
int
rte_pci_map_device(struct rte_pci_device *dev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return 0;
}

/* Unmap pci device */
void
rte_pci_unmap_device(struct rte_pci_device *dev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
}

int
pci_update_device(const struct rte_pci_addr *addr __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return 0;
}

/* Read PCI config space. */
int
rte_pci_read_config(const struct rte_pci_device *dev __rte_unused,
	void *buf __rte_unused, size_t len __rte_unused,
	off_t offset __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return 0;
}

/* Write PCI config space. */
int
rte_pci_write_config(const struct rte_pci_device *dev __rte_unused,
	const void *buf __rte_unused, size_t len __rte_unused,
	off_t offset __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return 0;
}

enum rte_iova_mode
pci_device_iova_mode(const struct rte_pci_driver *pdrv __rte_unused,
		const struct rte_pci_device *pdev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return RTE_IOVA_DC;
}

int
rte_pci_ioport_map(struct rte_pci_device *dev __rte_unused,
	int bar __rte_unused, struct rte_pci_ioport *p __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return -1;
}


void
rte_pci_ioport_read(struct rte_pci_ioport *p __rte_unused,
	void *data __rte_unused, size_t len __rte_unused,
	off_t offset __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
}

int
rte_pci_ioport_unmap(struct rte_pci_ioport *p __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return -1;
}

bool
pci_device_iommu_support_va(const struct rte_pci_device *dev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return false;
}

void
rte_pci_ioport_write(struct rte_pci_ioport *p __rte_unused,
		const void *data __rte_unused, size_t len __rte_unused,
		off_t offset __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
}

/* remap the PCI resource of a PCI device in anonymous virtual memory */
int
pci_uio_remap_resource(struct rte_pci_device *dev __rte_unused)
{
	/* This function is not implemented on Windows.
	 * We really should short-circuit the call to these functions by
	 * clearing the RTE_PCI_DRV_NEED_MAPPING flag
	 * in the rte_pci_driver flags.
	 */
	return -1;
}

static int
send_ioctl(HANDLE f, DWORD ioctl,
	void *in_buf, DWORD in_buf_size, void *out_buf, DWORD out_buf_size)
{
	BOOL res;
	DWORD bytes_ret = 0;

	res = DeviceIoControl(f, ioctl, in_buf, in_buf_size,
		out_buf, out_buf_size, &bytes_ret, NULL);
	if (!res) {
		RTE_LOG_WIN32_ERR("DeviceIoControl:IOCTL query failed");
		return -1;
	}

	return ERROR_SUCCESS;
}

/*
 * get device resource information by sending ioctl to netuio driver
 */
static int
get_netuio_device_info(HDEVINFO dev_info, PSP_DEVINFO_DATA dev_info_data,
	struct rte_pci_device *dev)
{
	int ret = -1;
	BOOL res;
	DWORD required_size = 0;
	TCHAR dev_instance_id[MAX_DEVICENAME_SZ];
	HANDLE netuio = INVALID_HANDLE_VALUE;
	HDEVINFO di_set = INVALID_HANDLE_VALUE;
	SP_DEVICE_INTERFACE_DATA  dev_ifx_data = { 0 };
	PSP_DEVICE_INTERFACE_DETAIL_DATA dev_ifx_detail = NULL;
	struct device_info hw_info = { 0 };
	unsigned int idx;
	DEVPROPTYPE property_type;
	DWORD numa_node;

	/* obtain the driver interface for this device */
	res = SetupDiGetDeviceInstanceId(dev_info, dev_info_data,
		dev_instance_id, sizeof(dev_instance_id), &required_size);
	if (!res) {
		RTE_LOG_WIN32_ERR("SetupDiGetDeviceInstanceId");
		return -1;
	}

	/* obtain the device information set */
	di_set = SetupDiGetClassDevs(&GUID_DEVINTERFACE_NETUIO, dev_instance_id,
		NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (di_set == INVALID_HANDLE_VALUE) {
		RTE_LOG_WIN32_ERR("SetupDiGetClassDevs(device information set)");
		return -1;
	}

	dev_ifx_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	/* enumerate the netUIO interfaces for this device information set */
	res = SetupDiEnumDeviceInterfaces(di_set, 0, &GUID_DEVINTERFACE_NETUIO,
		0, &dev_ifx_data);
	if (!res) {
		RTE_LOG_WIN32_ERR("SetupDiEnumDeviceInterfaces: no device interface");
		goto end;
	}

	/* request and allocate required size for the device interface detail */
	required_size = 0;
	res = SetupDiGetDeviceInterfaceDetail(di_set, &dev_ifx_data, NULL, 0,
		&required_size, NULL);
	if (!res) {
		/* ERROR_INSUFFICIENT_BUFFER is expected */
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			RTE_LOG_WIN32_ERR("SetupDiGetDeviceInterfaceDetail");
			goto end;
		}
	}

	dev_ifx_detail = malloc(required_size);
	if (!dev_ifx_detail) {
		RTE_LOG(ERR, EAL, "Could not allocate memory for dev interface.\n");
		goto end;
	}
	dev_ifx_detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

	res = SetupDiGetDeviceInterfaceDetail(di_set, &dev_ifx_data,
		dev_ifx_detail, required_size, NULL, NULL);
	if (!res) {
		RTE_LOG_WIN32_ERR("SetupDiGetDeviceInterfaceDetail");
		goto end;
	}

	/* open the kernel driver */
	netuio = CreateFile(dev_ifx_detail->DevicePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (netuio == INVALID_HANDLE_VALUE) {
		RTE_LOG_WIN32_ERR("CreateFile");
		RTE_LOG(ERR, EAL, "Unable to open driver file \"%s\".\n",
			dev_ifx_detail->DevicePath);
		goto end;
	}

	/* send ioctl to retrieve device information */
	if (send_ioctl(netuio, IOCTL_NETUIO_MAP_HW_INTO_USERMODE, NULL, 0,
		&hw_info, sizeof(hw_info)) != ERROR_SUCCESS) {
		RTE_LOG(ERR, EAL, "Unable to send ioctl to driver.\n");
		goto end;
	}

	/* set relevant values into the dev structure */
	for (idx = 0; idx < PCI_MAX_RESOURCE; idx++) {
		dev->mem_resource[idx].phys_addr =
		    hw_info.hw[idx].phys_addr.QuadPart;
		dev->mem_resource[idx].addr =
		    hw_info.hw[idx].user_mapped_virt_addr;
		dev->mem_resource[idx].len = hw_info.hw[idx].size;
	}

	/* get NUMA node using DEVPKEY_Device_Numa_Node */
	res = SetupDiGetDevicePropertyW(dev_info, dev_info_data,
		&DEVPKEY_Device_Numa_Node, &property_type,
		(BYTE *)&numa_node, sizeof(numa_node), NULL, 0);
	if (!res) {
		RTE_LOG_WIN32_ERR(
			"SetupDiGetDevicePropertyW(DEVPKEY_Device_Numa_Node)");
		goto end;
	}
	dev->device.numa_node = numa_node;

	ret = ERROR_SUCCESS;
end:
	if (netuio != INVALID_HANDLE_VALUE)
		CloseHandle(netuio);

	if (dev_ifx_detail)
		free(dev_ifx_detail);

	if (di_set != INVALID_HANDLE_VALUE)
		SetupDiDestroyDeviceInfoList(di_set);

	return ret;
}

static int
get_device_resource_info(HDEVINFO dev_info,
	PSP_DEVINFO_DATA dev_info_data, struct rte_pci_device *dev)
{
	DEVPROPTYPE property_type;
	DWORD numa_node;
	BOOL  res;
	int ret;

	switch (dev->kdrv) {
	case RTE_KDRV_NONE:
		/* Get NUMA node using DEVPKEY_Device_Numa_Node */
		res = SetupDiGetDevicePropertyW(dev_info, dev_info_data,
			&DEVPKEY_Device_Numa_Node, &property_type,
			(BYTE *)&numa_node, sizeof(numa_node), NULL, 0);
		if (!res) {
			RTE_LOG_WIN32_ERR(
				"SetupDiGetDevicePropertyW"
				"(DEVPKEY_Device_Numa_Node)");
			return -1;
		}
		dev->device.numa_node = numa_node;
		/* mem_resource - Unneeded for RTE_KDRV_NONE */
		dev->mem_resource[0].phys_addr = 0;
		dev->mem_resource[0].len = 0;
		dev->mem_resource[0].addr = NULL;
		break;
	case RTE_KDRV_NIC_UIO:
		/* get device info from netuio kernel driver */
		ret = get_netuio_device_info(dev_info, dev_info_data, dev);
		if (ret != 0) {
			RTE_LOG(DEBUG, EAL,
				"Could not retrieve device info for PCI device "
				PCI_PRI_FMT,
				dev->addr.domain, dev->addr.bus,
				dev->addr.devid, dev->addr.function);
			return ret;
		}
		break;
	default:
		/* kernel driver type is unsupported */
		RTE_LOG(DEBUG, EAL,
			"Kernel driver type for PCI device " PCI_PRI_FMT ","
			" is unsupported",
			dev->addr.domain, dev->addr.bus,
			dev->addr.devid, dev->addr.function);
		return -1;
	}

	return ERROR_SUCCESS;
}

/*
 * get string that contains the list of hardware IDs for a device
 */
static int
get_pci_hardware_id(HDEVINFO dev_info, PSP_DEVINFO_DATA device_info_data,
	char *pci_device_info, size_t pci_device_info_len)
{
	BOOL  res;

	/* Retrieve PCI device IDs */
	res = SetupDiGetDeviceRegistryPropertyA(dev_info, device_info_data,
			SPDRP_HARDWAREID, NULL, (BYTE *)pci_device_info,
			pci_device_info_len, NULL);
	if (!res) {
		RTE_LOG_WIN32_ERR(
			"SetupDiGetDeviceRegistryPropertyA(SPDRP_HARDWAREID)");
		return -1;
	}

	return 0;
}

/*
 * parse the SPDRP_HARDWAREID output and assign to rte_pci_id
 */
static int
parse_pci_hardware_id(const char *buf, struct rte_pci_id *pci_id)
{
	int ids = 0;
	uint16_t vendor_id, device_id;
	uint32_t subvendor_id = 0;

	ids = sscanf_s(buf, "PCI\\VEN_%" PRIx16 "&DEV_%" PRIx16 "&SUBSYS_%"
	    PRIx32, &vendor_id, &device_id, &subvendor_id);
	if (ids != 3)
		return -1;

	pci_id->vendor_id = vendor_id;
	pci_id->device_id = device_id;
	pci_id->subsystem_device_id = subvendor_id >> 16;
	pci_id->subsystem_vendor_id = subvendor_id & 0xffff;
	return 0;
}

static void
set_kernel_driver_type(PSP_DEVINFO_DATA device_info_data,
	struct rte_pci_device *dev)
{
	/* set kernel driver type based on device class */
	if (IsEqualGUID((const void *)&(device_info_data->ClassGuid),
		(const void *)&GUID_DEVCLASS_NETUIO))
		dev->kdrv = RTE_KDRV_NIC_UIO;
	else
		dev->kdrv = RTE_KDRV_NONE;
}

static int
get_device_pci_address(HDEVINFO dev_info,
	PSP_DEVINFO_DATA device_info_data, struct rte_pci_addr *addr)
{
	BOOL  res;
	ULONG bus_num, dev_and_func;

	res = SetupDiGetDeviceRegistryProperty(dev_info, device_info_data,
		SPDRP_BUSNUMBER, NULL, (PBYTE)&bus_num, sizeof(bus_num), NULL);
	if (!res) {
		RTE_LOG_WIN32_ERR(
			"SetupDiGetDeviceRegistryProperty(SPDRP_BUSNUMBER)");
		return -1;
	}

	res = SetupDiGetDeviceRegistryProperty(dev_info, device_info_data,
		SPDRP_ADDRESS, NULL, (PBYTE)&dev_and_func, sizeof(dev_and_func),
		NULL);
	if (!res) {
		RTE_LOG_WIN32_ERR(
			"SetupDiGetDeviceRegistryProperty(SPDRP_ADDRESS)");
		return -1;
	}

	addr->domain = 0;
	addr->bus = bus_num;
	addr->devid = dev_and_func >> 16;
	addr->function = dev_and_func & 0xffff;
	return 0;
}

static int
pci_scan_one(HDEVINFO dev_info, PSP_DEVINFO_DATA device_info_data)
{
	struct rte_pci_device *dev;
	int ret = -1;
	char  pci_device_info[PATH_MAX];
	struct rte_pci_addr addr;
	struct rte_pci_id pci_id;

	dev = malloc(sizeof(*dev));
	if (dev == NULL)
		goto end;

	memset(dev, 0, sizeof(*dev));

	ret = get_pci_hardware_id(dev_info, device_info_data,
		pci_device_info, PATH_MAX);
	if (ret != 0)
		goto end;

	ret = parse_pci_hardware_id((const char *)&pci_device_info, &pci_id);
	if (ret != 0) {
		/*
		 * We won't add this device, but we want to continue
		 * looking for supported devices
		 */
		ret = ERROR_CONTINUE;
		goto end;
	}

	ret = get_device_pci_address(dev_info, device_info_data, &addr);
	if (ret != 0)
		goto end;

	dev->addr = addr;
	dev->id = pci_id;
	dev->max_vfs = 0; /* TODO: get max_vfs */

	pci_name_set(dev);

	set_kernel_driver_type(device_info_data, dev);

	/* get resources */
	if (get_device_resource_info(dev_info, device_info_data, dev)
			!= ERROR_SUCCESS) {
		goto end;
	}

	/* device is valid, add in list (sorted) */
	if (TAILQ_EMPTY(&rte_pci_bus.device_list)) {
		rte_pci_add_device(dev);
	} else {
		struct rte_pci_device *dev2 = NULL;
		int ret;

		TAILQ_FOREACH(dev2, &rte_pci_bus.device_list, next) {
			ret = rte_pci_addr_cmp(&dev->addr, &dev2->addr);
			if (ret > 0) {
				continue;
			} else if (ret < 0) {
				rte_pci_insert_device(dev2, dev);
			} else { /* already registered */
				dev2->kdrv = dev->kdrv;
				dev2->max_vfs = dev->max_vfs;
				memmove(dev2->mem_resource, dev->mem_resource,
					sizeof(dev->mem_resource));
				free(dev);
			}
			return 0;
		}
		rte_pci_add_device(dev);
	}

	return 0;
end:
	if (dev)
		free(dev);
	return ret;
}

/*
 * Scan for devices in specified device class
 * and add them into the devices list.
 */
static int
pci_scan_device_class(const GUID *guid)
{
	int   ret = -1;
	DWORD device_index = 0, found_device = 0;
	HDEVINFO dev_info;
	SP_DEVINFO_DATA device_info_data;
	const char *class;

	if (IsEqualGUID((const void *)guid,
	    (const void *)&GUID_DEVCLASS_NETUIO))
		class = netuio_class;
	else
		class = net_class;

	dev_info = SetupDiGetClassDevs(guid, TEXT("PCI"), NULL,	DIGCF_PRESENT);
	if (dev_info == INVALID_HANDLE_VALUE) {
		RTE_LOG_WIN32_ERR("SetupDiGetClassDevs(pci_scan)");
		RTE_LOG(ERR, EAL, "Unable to enumerate %s PCI devices.\n",
			    class);
		goto end;
	}

	device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
	device_index = 0;

	while (SetupDiEnumDeviceInfo(dev_info, device_index,
	    &device_info_data)) {
		device_index++;
		ret = pci_scan_one(dev_info, &device_info_data);
		if (ret == ERROR_SUCCESS)
			found_device++;
		else if (ret != ERROR_CONTINUE)
			goto end;

		memset(&device_info_data, 0, sizeof(SP_DEVINFO_DATA));
		device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
	}

	RTE_LOG(DEBUG, EAL, "PCI scan found %lu %s devices\n",
		found_device, class);
	ret = 0;
end:
	if (dev_info != INVALID_HANDLE_VALUE)
		SetupDiDestroyDeviceInfoList(dev_info);

	return ret;
}

/*
 * Scan the contents of the PCI bus looking for devices
 */
int
rte_pci_scan(void)
{
	int   ret = -1;

	/* for debug purposes, PCI can be disabled */
	if (!rte_eal_has_pci())
		return 0;

	/* first, scan for netUIO class devices */
	ret = pci_scan_device_class(&GUID_DEVCLASS_NETUIO);

	/* then, scan for the standard net class devices */
	ret = pci_scan_device_class(&GUID_DEVCLASS_NET);

	return ret;
}
