#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2024 Intel Corporation
#
"""Script to bind PCI devices to DPDK-compatible userspace IO drivers."""

import argparse
import glob
import grp
import json
import os
import pwd
import subprocess
import sys
import typing as T

# the following list of modules is supported by DPDK
DPDK_KERNEL_MODULES = {"igb_uio", "vfio-pci", "uio_pci_generic"}

# pattern matching criteria for various devices and devices classes. keys are entries in lspci,
# while values, if present are further matches for lspci criteria. values can be either strings or
# list of strings, in which case any match is sufficient.
StrOrList = T.Union[str, T.List[str]]
DeviceMatchPattern = T.Dict[str, StrOrList]
CLASS_NETWORK: DeviceMatchPattern = {
    "Class": "02",
}
CLASS_ACCELERATION: DeviceMatchPattern = {
    "Class": "12",
}
CLASS_IFPGA: DeviceMatchPattern = {
    "Class": "12",
    "Vendor": "8086",
    "Device": "0b30",
}
CLASS_ENCRYPTION: DeviceMatchPattern = {
    "Class": "10",
}
CLASS_INTEL_PROCESSOR: DeviceMatchPattern = {
    "Class": "0b",
    "Vendor": "8086",
}
DEVICE_CAVIUM_SSO: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": ["a04b", "a04d"],
}
DEVICE_CAVIUM_FPA: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a053",
}
DEVICE_CAVIUM_PKX: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": ["a0dd", "a049"],
}
DEVICE_CAVIUM_TIM: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a051",
}
DEVICE_CAVIUM_ZIP: DeviceMatchPattern = {
    "Class": "12",
    "Vendor": "177d",
    "Device": "a037",
}
DEVICE_AVP_VNIC: DeviceMatchPattern = {
    "Class": "05",
    "Vendor": "1af4",
    "Device": "1110",
}
DEVICE_CNXK_BPHY: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a089",
}
DEVICE_CNXK_BPHY_CGX: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": ["a059", "a060"],
}
DEVICE_CNXK_DMA: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a081",
}
DEVICE_CNXK_INL_DEV: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": ["a0f0", "a0f1"],
}
DEVICE_HISILICON_DMA: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "19e5",
    "Device": "a122",
}
DEVICE_ODM_DMA: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a08c",
}
DEVICE_INTEL_DLB: DeviceMatchPattern = {
    "Class": "0b",
    "Vendor": "8086",
    "Device": ["270b", "2710", "2714"],
}
DEVICE_INTEL_IOAT_BDW: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "8086",
    "Device": [
        "6f20",
        "6f21",
        "6f22",
        "6f23",
        "6f24",
        "6f25",
        "6f26",
        "6f27",
        "6f2e",
        "6f2f",
    ],
}
DEVICE_INTEL_IOAT_SKX: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "8086",
    "Device": "2021",
}
DEVICE_INTEL_IOAT_ICX: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "8086",
    "Device": "0b00",
}
DEVICE_INTEL_IDXD_SPR: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "8086",
    "Device": "0b25",
}
DEVICE_INTEL_NTB_SKX: DeviceMatchPattern = {
    "Class": "06",
    "Vendor": "8086",
    "Device": "201c",
}
DEVICE_INTEL_NTB_ICX: DeviceMatchPattern = {
    "Class": "06",
    "Vendor": "8086",
    "Device": "347e",
}
DEVICE_CNXK_SSO: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": ["a0f9", "a0fa"],
}
DEVICE_CNXK_NPA: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": ["a0fb", "a0fc"],
}
DEVICE_CN9K_REE: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a0f4",
}
DEVICE_VIRTIO_BLK: DeviceMatchPattern = {
    "Class": "01",
    "Vendor": "1af4",
    "Device": ["1001", "1042"],
}
DEVICE_CNXK_ML: DeviceMatchPattern = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a092",
}

# device types as recognized by devbind
NETWORK_DEVICES = [CLASS_NETWORK, CLASS_IFPGA, DEVICE_CAVIUM_PKX, DEVICE_AVP_VNIC]
BASEDBAND_DEVICES = [CLASS_ACCELERATION]
CRYPTO_DEVICES = [CLASS_ENCRYPTION, CLASS_INTEL_PROCESSOR]
DMA_DEVICES = [
    DEVICE_CNXK_DMA,
    DEVICE_HISILICON_DMA,
    DEVICE_INTEL_IDXD_SPR,
    DEVICE_INTEL_IOAT_BDW,
    DEVICE_INTEL_IOAT_ICX,
    DEVICE_INTEL_IOAT_SKX,
    DEVICE_ODM_DMA,
]
EVENTDEV_DEVICES = [
    DEVICE_CAVIUM_SSO,
    DEVICE_CAVIUM_TIM,
    DEVICE_INTEL_DLB,
    DEVICE_CNXK_SSO,
]
MEMPOOL_DEVICES = [DEVICE_CAVIUM_FPA, DEVICE_CNXK_NPA]
COMPRESS_DEVICES = [DEVICE_CAVIUM_ZIP]
REGEX_DEVICES = [DEVICE_CN9K_REE]
ML_DEVICES = [DEVICE_CNXK_ML]
MISC_DEVICES = [
    DEVICE_CNXK_BPHY,
    DEVICE_CNXK_BPHY_CGX,
    DEVICE_CNXK_INL_DEV,
    DEVICE_INTEL_NTB_SKX,
    DEVICE_INTEL_NTB_ICX,
    DEVICE_VIRTIO_BLK,
]
# which command line arguments/printouts correspond to which device types
DEVICE_TYPE_ALL = "all"
DEVICE_TYPE_NET = "net"
DEVICE_TYPE_BASEBAND = "baseband"
DEVICE_TYPE_CRYPTO = "crypto"
DEVICE_TYPE_DMA = "dma"
DEVICE_TYPE_EVENT = "event"
DEVICE_TYPE_MEMPOOL = "mempool"
DEVICE_TYPE_COMPRESS = "compress"
DEVICE_TYPE_REGEX = "regex"
DEVICE_TYPE_ML = "ml"
DEVICE_TYPE_MISC = "misc"
DEVICE_TYPES = {
    # device type: (printout name, device match pattern)
    DEVICE_TYPE_NET: ("Network", NETWORK_DEVICES),
    DEVICE_TYPE_BASEBAND: ("Baseband", BASEDBAND_DEVICES),
    DEVICE_TYPE_CRYPTO: ("Crypto", CRYPTO_DEVICES),
    DEVICE_TYPE_DMA: ("DMA", DMA_DEVICES),
    DEVICE_TYPE_EVENT: ("Eventdev", EVENTDEV_DEVICES),
    DEVICE_TYPE_MEMPOOL: ("Mempool", MEMPOOL_DEVICES),
    DEVICE_TYPE_COMPRESS: ("Compress", COMPRESS_DEVICES),
    DEVICE_TYPE_REGEX: ("Regex", REGEX_DEVICES),
    DEVICE_TYPE_ML: ("ML", ML_DEVICES),
    DEVICE_TYPE_MISC: ("Misc", MISC_DEVICES),
}


class DevbindError(Exception):
    """Generic error to be displayed by devbind."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


def category_key_match(key: str, value: str, pattern: StrOrList) -> bool:
    """Check if value matches the pattern according to key match rules."""
    # if pattern is a list of strings, recurse and check each item
    if isinstance(pattern, list):
        return any(
            category_key_match(key, value, pattern_item) for pattern_item in pattern
        )
    # pattern is a single string, use single string match rules
    if key == "Class":
        # special case for Class: it has to match from the beginning
        return value.startswith(pattern)
    # default case: exact match
    return value == pattern


def parse_lspci_line(line: str) -> T.Dict[str, str]:
    """Parse lspci line and return a dictionary."""
    # the format can be either:
    #   key: value
    # or
    #   key: string representation [value]
    # we want to store both because we may want to display both
    res: T.Dict[str, str] = {}
    name, value = line.split("\t", 1)
    name = name.strip().rstrip(":")
    value = value.strip()
    # does this value have string representation?
    value_list = value.rsplit(" ", 1)
    if len(value_list) > 1:
        value_str, value = value_list
        # store string representation
        res[name + "_str"] = value_str
    # strip out brackets
    value = value.strip("[]")
    res[name] = value

    return res


def resolve_pci_glob(dev: str) -> T.List[str]:
    """Returns a list of PCI devices matching a glob pattern."""
    pci_sysfs_path = "/sys/bus/pci/devices"
    for _glob in [dev, "0000:" + dev]:
        paths = [
            os.path.basename(path)
            for path in glob.glob(os.path.join(pci_sysfs_path, _glob))
        ]
        if paths:
            return paths
    return [dev]


def check_installed(program: str, package: str) -> None:
    """Check if a program is installed."""
    if subprocess.call(
        ["which", program], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ):
        raise DevbindError(f"'{program}' not found - please install '{package}'.")


def read_output(args: T.List[str]) -> str:
    """Run a subprocess, collect its output, and return it as a list of lines."""
    try:
        output = subprocess.check_output(args).decode("utf-8")
    except subprocess.CalledProcessError as e:
        raise DevbindError(f"Error running '{' '.join(args)}': {e}") from e
    return output


def read_routed_interfaces() -> T.List[str]:
    """Find interfaces with active routes."""
    try:
        # use ip route's JSON output to get a list of active interfaces
        routes = json.loads(read_output(["ip", "-j", "route"]))
    except json.JSONDecodeError as e:
        raise DevbindError(f"Error parsing 'ip route' output: {e}") from e
    # find interfaces with active routes
    routed_ifs: T.List[str] = []
    for route in routes:
        # skip uninteresting routes
        if "169.254" in route["dst"]:
            continue
        if "dev" in route:
            routed_ifs.append(route["dev"])
    # dedupe list
    return list(set(routed_ifs))


def sysfs_read_pci_drivers() -> T.List[str]:
    """Gather all PCI modules loaded on the system."""
    return os.listdir("/sys/bus/pci/drivers")


def sysfs_device_get_path(dev: str, path: str) -> str:
    """Construct path in device sysfs directory."""
    return os.path.join("/sys/bus/pci/devices", dev, path)


def sysfs_driver_get_path(driver: str, path: str) -> str:
    """Construct path in driver sysfs directory."""
    return os.path.join("/sys/bus/pci/drivers", driver, path)


def sysfs_iommu_enabled() -> bool:
    """Check if IOMMU is enabled on the system."""
    return len(os.listdir("/sys/class/iommu")) > 0


def sysfs_enable_unsafe_noiommu() -> None:
    """Enable unsafe no-IOMMU mode."""
    fname = "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode"
    try:
        with open(fname, "r", encoding="utf-8") as f:
            val = f.read()
        if val in ["1", "Y", "y"]:
            # already enabled
            return
    except OSError as e:
        raise DevbindError(f"Cannot read unsafe no IOMMU mode status: {e}") from e
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write("1")
    except OSError as e:
        raise DevbindError(f"Cannot write unsafe no IOMMU mode status: {e}") from e
    print(
        "Warning: IOMMU is not enabled, enabling unsafe no-IOMMU mode for VFIO drivers."
    )


def sysfs_get_vfio_device(dev: str) -> str:
    """Get VFIO device file for a PCI device."""
    iommu_grp_base_path = sysfs_device_get_path(dev, "iommu_group")
    # extract group number from base path
    iommu_grp = os.path.basename(os.readlink(iommu_grp_base_path))
    # find VFIO device corresponding to this IOMMU group
    return os.path.join("/dev/vfio", iommu_grp)


def device_vfio_set_ownership(dev: str, uid: int, gid: int) -> None:
    """Set device ownership."""
    try:
        os.chown(sysfs_get_vfio_device(dev), uid, gid)
    except OSError as e:
        raise DevbindError(f"Failed to set device ownership for {dev}: {e}") from e


class Device:
    """Thin wrapper around a device dict read from lspci."""

    def __init__(self, dev_dict: T.Dict[str, str]):
        self._dev_dict = dev_dict
        self.slot = self._dev_dict["Slot"]

        # find kernel interfaces for this device
        self._update_interfaces()

    def __str__(self) -> str:
        return self.slot

    def __getitem__(self, key: str) -> str:
        """Get value as it appears in the device dictionary."""
        return self._get_str(key)

    def _set_value(self, key: str, value: StrOrList):
        """Generic setter for different fields."""
        if value:
            # value can be a list or a string
            if isinstance(value, list):
                self._dev_dict[key] = ",".join(value)
            else:
                self._dev_dict[key] = value
        elif key in self._dev_dict:
            # delete key if value is empty
            del self._dev_dict[key]

    def _get_str(self, key: str) -> str:
        """Generic getter for string fields."""
        if key in self._dev_dict:
            return self._dev_dict[key]
        return ""

    def _get_list(self, key: str) -> T.List[str]:
        """Generic getter for list fields."""
        if key in self._dev_dict:
            return [m.strip() for m in self._dev_dict[key].split(",")]
        return []

    def _update_interfaces(self):
        """Update interfaces for this device."""
        sysfs_path = sysfs_device_get_path(self.slot, "net")
        try:
            self.interfaces = os.listdir(sysfs_path)
        except OSError:
            pass

    def update(self):
        """Update device information from lspci."""
        self._dev_dict.clear()
        lspci_output = read_output(["lspci", "-Dvmmnnks", self.slot])
        for line in lspci_output.splitlines():
            if not line:
                continue
            self._dev_dict.update(parse_lspci_line(line))
        self._update_interfaces()

    def match(self, pattern: DeviceMatchPattern) -> bool:
        """Check if this device matches the pattern."""
        for key, match_pattern in pattern.items():
            if key not in self._dev_dict:
                return False
            value = self._dev_dict[key]
            if not category_key_match(key, value, match_pattern):
                return False
        return True

    @property
    def driver(self) -> str:
        """Get driver bound for this device."""
        return self._get_str("Driver")

    @driver.setter
    def driver(self, driver: str):
        """Set driver for this device."""
        self._set_value("Driver", driver)

    @property
    def modules(self) -> T.List[str]:
        """Get compatible modules for this device."""
        return self._get_list("Module")

    @modules.setter
    def modules(self, modules: T.List[str]):
        """Set compatible modules for this device."""
        self._set_value("Module", modules)

    @property
    def interfaces(self) -> T.List[str]:
        """Get interfaces for this device."""
        return self._get_list("Interface")

    @interfaces.setter
    def interfaces(self, interfaces: T.List[str]):
        """Set interfaces for this device."""
        self._set_value("Interface", interfaces)

    @property
    def active_interface(self) -> bool:
        """Return active interface information."""
        return bool(self._get_str("Active"))

    @active_interface.setter
    def active_interface(self, active: bool):
        """Set active interface information."""
        self._set_value("Active", "*Active*" if active else "")


def read_devices_from_lspci() -> T.Iterable[Device]:
    """Read devices from lspci."""
    lspci_output = read_output(["lspci", "-Dvmmnnk"])
    cur_device: T.Dict[str, str] = {}
    for line in lspci_output.splitlines():
        if not line:
            dev = Device(cur_device)
            yield dev
            cur_device = {}
        else:
            cur_device.update(parse_lspci_line(line))


class Devbind:
    """Class to cover various devbind-related operations and data."""

    def __init__(self) -> None:
        # gather all loaded kernel modules
        self.loaded_pci_modules = sysfs_read_pci_drivers()
        # find which ones are UIO modules
        self.uio_modules = self._find_loaded_uio_modules()
        # gather all routed interfaces
        self._routed_interfaces = read_routed_interfaces()

        # all detected PCI devices, keyed by PCI D:B:D.F
        self.pci_devices: T.Dict[str, Device] = {}
        # list of devices by type
        self.devices_by_type: T.Dict[str, T.List[Device]] = {
            devtype: [] for devtype in DEVICE_TYPES
        }
        # scan all PCI devices
        for dev in read_devices_from_lspci():
            # categorize device
            devtype = self._find_device_type(dev)
            if devtype:
                self.devices_by_type[devtype].append(dev)

            # fixup module and driver fields
            self._add_uio_modules(dev)

            # special case: find if any interfaces are active. non-network interfaces will not have
            # any interfaces at all, so it's safe to check all devices. we never update this
            # information, because once we start binding/unbinding, we have already acted on it.
            if any(iface in self._routed_interfaces for iface in dev.interfaces):
                dev.active_interface = True

            # save the device in common list
            self.pci_devices[dev.slot] = dev

    def _find_device_type(self, dev: Device) -> str:
        """Match a device against known device types."""
        for devtype, dt_tup in DEVICE_TYPES.items():
            _, patterns = dt_tup
            for pattern in patterns:
                if dev.match(pattern):
                    return devtype
        return ""

    def _find_loaded_uio_modules(self) -> T.List[str]:
        loaded = set(self.loaded_pci_modules)
        supported = set(DPDK_KERNEL_MODULES)
        return list(loaded & supported)

    def _add_uio_modules(self, dev: Device) -> None:
        """Add loaded UIO modules to list of available modules."""
        # add UIO modules to list of supported modules
        modules = set(dev.modules + self.uio_modules)

        # make sure driver and module string do not have any duplicates
        if dev.driver in modules:
            modules.remove(dev.driver)

        # update list of compatible modules
        dev.modules = list(modules)

    def resolve_device(self, devstr: str) -> str:
        """Try to resolve a device into a PCI D:B:D:F."""
        # is this already a valid device?
        if devstr in self.pci_devices:
            return devstr
        # can we append domain to it?
        if "0000:" + devstr in self.pci_devices:
            return "0000:" + devstr
        # can we find a network interface name?
        for dev in self.devices_by_type[DEVICE_TYPE_NET]:
            if devstr in dev.interfaces:
                return dev.slot
        # we can't figure out what this is
        raise ValueError(
            f"Unknown device '{devstr}'. Please specify device in 'bus:slot.func' format."
        )

    def _can_modify(self, dev: Device, driver: str, force: bool) -> bool:
        """Check if we should attempt to modify this device."""
        # are we allowed to modify this device?
        if dev.active_interface and not force:
            print(
                f"Warning: routing table indicates that interface {dev} is active. "
                "Not modifying.",
                file=sys.stderr,
            )
            return False

        # does this device already use the driver we want to use?
        cur_driver = dev.driver
        if cur_driver == driver:
            # are we binding or unbinding?
            if driver:
                print(
                    f"Notice: {dev} is already bound to driver {driver}, skipping bind",
                    file=sys.stderr,
                )
            else:
                print(
                    f"Notice: {dev} is not managed by any driver, skipping unbind",
                    file=sys.stderr,
                )
            return False

        # all checks passed
        return True

    def unbind(self, dev: Device, force: bool) -> None:
        """Unbind one device from its current driver."""
        if not self._can_modify(dev, "", force):
            return
        cur_drv = dev.driver
        unbind_path = sysfs_driver_get_path(cur_drv, "unbind")

        print(f"Unbinding {dev} from {cur_drv}...")

        try:
            with open(unbind_path, "w", encoding="utf-8") as f:
                f.write(dev.slot)
        except OSError as e:
            raise DevbindError(f"Unbind failed for {dev}: {e}") from e
        # update device state
        dev.update()
        self._add_uio_modules(dev)

    def bind(self, dev: Device, driver: str, force: bool) -> None:
        """Bind one device to the specified driver."""
        if not self._can_modify(dev, driver, force):
            return
        override_path = sysfs_device_get_path(dev.slot, "driver_override")
        bind_path = sysfs_driver_get_path(driver, "bind")

        print(f"Binding {dev} to {driver}...")

        # are we binding to UIO module?
        if driver in self.uio_modules:
            try:
                with open(override_path, "w", encoding="utf-8") as f:
                    f.write(driver)
            except OSError as e:
                raise DevbindError(f"Driver override failed for {dev}: {e}") from e

        # bind driver to device
        try:
            with open(bind_path, "a", encoding="utf-8") as f:
                f.write(dev.slot)
        except OSError as e:
            raise DevbindError(f"Bind failed for {dev}: {e}") from e
        # update device state
        dev.update()
        self._add_uio_modules(dev)

        # driver_override caches its value, so clean up by writing empty string
        try:
            with open(override_path, "w", encoding="utf-8") as f:
                f.write("\00")
        except OSError as e:
            raise DevbindError(f"CLeanup failed for {dev}: {e}") from e


class DevbindCtx:
    """POD class to keep command-line arguments and context."""

    def __init__(self) -> None:
        self.status = False
        self.bind = False
        self.status_group: str
        self.driver: str
        self.devices: T.List[str]
        self.force: bool
        self.noiommu: bool
        self.vfio_uid: int
        self.vfio_gid: int

        self.devbind: Devbind


def bind_devices(ctx: DevbindCtx) -> None:
    """Bind devices to the specified driver."""
    devbind = ctx.devbind
    use_vfio = ctx.driver == "vfio-pci"

    # a common user error is to forget to specify the driver the devices need to be bound to. check
    # if the driver is a valid device, and if it is, show a meaningful error.
    try:
        devbind.resolve_device(ctx.driver)
        # if we got here, the driver is a valid device, which is an error
        raise DevbindError(f"""\
Driver '{ctx.driver}' does not look like a valid driver. Did you
forget to specify the driver to bind the devices to?""")
    except ValueError:
        # driver generated error - it's not a valid device
        pass

    # validate all devices
    try:
        ctx.devices = [devbind.resolve_device(dev) for dev in ctx.devices]
    except ValueError as e:
        raise DevbindError(str(e)) from e
    devices = (devbind.pci_devices[dbdf] for dbdf in ctx.devices)

    # do we want to unbind?
    if not ctx.driver:
        # unbind devices
        for dev in devices:
            devbind.unbind(dev, ctx.force)
        return

    # validate driver
    if ctx.driver not in devbind.loaded_pci_modules:
        raise DevbindError(f"Driver '{ctx.driver}' is not loaded.")

    # check for IOMMU support
    if use_vfio and not sysfs_iommu_enabled():
        sysfs_enable_unsafe_noiommu()

    # bind all devices
    for dev in devices:
        rollback_driver = dev.driver
        # does this device have a driver already? if so, unbind
        if rollback_driver:
            devbind.unbind(dev, ctx.force)

        # device doesn't have any driver now, bind it
        try:
            devbind.bind(dev, ctx.driver, ctx.force)
            # bind succeeded, rollback no longer necessary
            rollback_driver = ""
        except DevbindError as e:
            # should we roll back?
            if rollback_driver:
                print(f"Warning: {e}")
            else:
                # pass the error up the stack
                raise
        if rollback_driver:
            devbind.bind(dev, rollback_driver, ctx.force)
            return

        # if we're binding to vfio-pci, set IOMMU user/group ownership if one was specified
        if use_vfio and (ctx.vfio_uid != -1 or ctx.vfio_gid != -1):
            device_vfio_set_ownership(dev.slot, ctx.vfio_uid, ctx.vfio_gid)


def print_status_section(title: str, section_devs: T.List[Device]) -> None:
    """Prints subsection of device status (e.g. only kernel devices)."""
    # we will sort strings before printing
    strings: T.List[str] = []

    def _fmt_key_val(name: str, value: str) -> str:
        """Generate a devbind device printout string for a particular value."""
        # if there's a name provided, include it in the output
        if name and value:
            return f"{name}={value}"
        # otherwise just print the value, including empty ones
        return value

    # generate device strings
    for dev in section_devs:
        # construct strings
        devstr = f'{dev["Device_str"]} {dev["Device"]}'
        strs = [
            dev.slot,
            f"'{devstr}'",
            _fmt_key_val("drv", dev["Driver"]),
            _fmt_key_val("unused", dev["Module"]),
            _fmt_key_val("if", dev["Interface"]),
            _fmt_key_val("numa_node", dev["NUMANode"]),
            _fmt_key_val("", dev["Active"]),
        ]
        # filter out empty strings and join
        strings.append(" ".join(filter(None, strs)))
    strings.sort()
    print(f"{title}")
    print("=" * len(title))
    print("\n".join(strings))
    print()


def print_status_group(
    ctx: DevbindCtx, group_title: str, group_devs: T.List[Device]
) -> None:
    """Print status for a specific device group."""
    # do we have any devices at all?
    if not group_devs:
        msg = f"No {group_title} devices found."
        print(msg)
        print("=" * len(msg))
        print()
        return

    # split out all devices into three groups: kernel, non-kernel, and unbound
    kernel: T.List[Device] = []
    dpdk: T.List[Device] = []
    unbound: T.List[Device] = []

    for dev in group_devs:
        driver = dev.driver
        if driver in ctx.devbind.uio_modules:
            dpdk.append(dev)
        elif driver:
            kernel.append(dev)
        else:
            unbound.append(dev)

    # print out each group
    if dpdk:
        print_status_section(
            f"{group_title} devices using DPDK-compatible driver", dpdk
        )
    if kernel:
        print_status_section(f"{group_title} devices using kernel driver", kernel)
    if unbound:
        print_status_section(f"Other {group_title} devices", unbound)


def print_status(ctx: DevbindCtx) -> None:
    """Print status of all devices."""
    # device_type to devbind type mapping
    for group_name, dt_t in DEVICE_TYPES.items():
        if ctx.status_group in [DEVICE_TYPE_ALL, group_name]:
            group_title, _ = dt_t
            group_devs = ctx.devbind.devices_by_type[group_name]
            print_status_group(ctx, group_title, group_devs)


def parse_args() -> DevbindCtx:
    """Parse command-line arguments into devbind context."""

    parser = argparse.ArgumentParser(
        description="Utility to bind and unbind devices from Linux kernel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
---------

To display current device status:
        %(prog)s --status

To display current network device status:
        %(prog)s --status net

To bind eth1 from the current driver and move to use vfio-pci
        %(prog)s --bind=vfio-pci eth1

To unbind 0000:01:00.0 from using any driver
        %(prog)s -u 0000:01:00.0

To bind 0000:02:00.0 and 0000:02:00.1 to the ixgbe kernel driver
        %(prog)s -b ixgbe 02:00.0 02:00.1
""",
    )

    status_choices = [DEVICE_TYPE_ALL] + list(DEVICE_TYPES.keys())

    parser.add_argument(
        "-s",
        "--status",
        # backwards compatibility
        "--status-dev",
        # None if flag was not specified
        default=None,
        # "all" if flag was specified without arguments
        const=DEVICE_TYPE_ALL,
        # otherwise, match against the choice table
        nargs="?",
        choices=status_choices,
        help="Print the status of device group (default: all devices).",
    )
    bind_action = parser.add_mutually_exclusive_group()
    bind_action.add_argument(
        "-b",
        "--bind",
        metavar="DRIVER",
        help='Select the driver to use ("none" to unbind the device)',
    )
    bind_action.add_argument(
        "-u",
        "--unbind",
        action="store_true",
        help='Unbind a device (equivalent to "-b none")',
    )
    parser.add_argument(
        "--noiommu-mode",
        action="store_true",
        help="If IOMMU is not available, enable no IOMMU mode for VFIO drivers",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="""\
Override restriction on binding devices in use by Linux. WARNING: This can lead
to loss of network connection and should be used with caution.
""",
    )
    parser.add_argument(
        "-G",
        "--gid",
        type=lambda g: grp.getgrnam(g).gr_gid,
        default=-1,
        help="For VFIO, specify the group ID to set IOMMU group ownership",
    )
    parser.add_argument(
        "-U",
        "--uid",
        type=lambda u: pwd.getpwnam(u).pw_uid,
        default=-1,
        help="For VFIO, specify the user ID to set IOMMU group ownership",
    )
    parser.add_argument(
        "devices",
        metavar="DEVICE",
        nargs="*",
        help="""\
Device specified as PCI "domain:bus:slot.func" syntax or "bus:slot.func" syntax.
For devices bound to Linux kernel drivers, they may be referred to by interface name.
""",
    )

    opt = parser.parse_args()

    ctx = DevbindCtx()

    if opt.status:
        ctx.status = True
        ctx.status_group = opt.status
    if opt.bind or opt.unbind:
        ctx.bind = True
        ctx.driver = "" if opt.unbind else opt.bind
        # support any capitalization for binding to "none"
        if ctx.driver.lower() == "none":
            ctx.driver = ""
    if not ctx.status and not ctx.bind:
        print("Error: No action specified.", file=sys.stderr)
        parser.print_usage()
        sys.exit(1)

    ctx.noiommu = opt.noiommu_mode
    ctx.force = opt.force
    ctx.devices = opt.devices
    ctx.vfio_uid = opt.uid
    ctx.vfio_gid = opt.gid

    # if status is displayed, devices shouldn't be passed
    if not ctx.bind and ctx.devices:
        print("Error: Devices should not be specified with --status action.")
        parser.print_usage()
        sys.exit(1)
    # if bind is used, devices should be passed
    elif ctx.bind and not ctx.devices:
        print("Error: No devices specified for --bind/--unbind action.")
        parser.print_usage()
        sys.exit(1)
    return ctx


def _main():
    ctx = parse_args()

    # initialize devbind data
    ctx.devbind = Devbind()

    if ctx.bind:
        # resolve any PCI globs in devices
        ctx.devices = [d for dev in ctx.devices for d in resolve_pci_glob(dev)]
        bind_devices(ctx)
        print()
    if ctx.status:
        print_status(ctx)


if __name__ == "__main__":
    try:
        # check if lspci and ip are installed before doing anything
        check_installed("lspci", "pciutils")
        check_installed("ip", "iproute2")

        # run the main function
        _main()
    except DevbindError as e:
        sys.exit(f"Error: {e}")
