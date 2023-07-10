# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire

import re

from framework.config import InteractiveApp
from framework.remote_session import TestPmdShell
from framework.settings import SETTINGS
from framework.test_suite import TestSuite


class SmokeTests(TestSuite):
    is_blocking = True
    # dicts in this list are expected to have two keys:
    # "pci_address" and "current_driver"
    nics_in_node: list[dict[str, str]] = []

    def set_up_suite(self) -> None:
        """
        Setup:
            Set the build directory path and generate a list of NICs in the SUT node.
        """
        self.dpdk_build_dir_path = self.sut_node.remote_dpdk_build_dir
        for nic in self.sut_node.config.ports:
            new_dict = {
                "pci_address": nic.pci,
                "current_driver": nic.os_driver.strip(),
            }
            self.nics_in_node.append(new_dict)

    def test_unit_tests(self) -> None:
        """
        Test:
            Run the fast-test unit-test suite through meson.
        """
        self.sut_node.main_session.send_command(
            f"meson test -C {self.dpdk_build_dir_path} --suite fast-tests",
            300,
            verify=True,
        )

    def test_driver_tests(self) -> None:
        """
        Test:
            Run the driver-test unit-test suite through meson.
        """
        list_of_vdevs = ""
        for dev in self.sut_node._execution_config.vdevs:
            list_of_vdevs += f"--vdev {dev} "
        list_of_vdevs = list_of_vdevs[:-1]
        if list_of_vdevs:
            self._logger.info(
                "Running driver tests with the following virtual "
                f"devices: {list_of_vdevs}"
            )
            self.sut_node.main_session.send_command(
                f"meson test -C {self.dpdk_build_dir_path} --suite driver-tests "
                f'--test-args "{list_of_vdevs}"',
                300,
                verify=True,
            )
        else:
            self.sut_node.main_session.send_command(
                f"meson test -C {self.dpdk_build_dir_path} --suite driver-tests",
                300,
                verify=True,
            )

    def test_devices_listed_in_testpmd(self) -> None:
        """
        Test:
            Uses testpmd driver to verify that devices have been found by testpmd.
        """
        testpmd_driver = self.sut_node.create_interactive_shell(InteractiveApp.testpmd)
        # We know it should always be a TestPmdShell but mypy doesn't
        assert isinstance(testpmd_driver, TestPmdShell)
        dev_list: list[str] = testpmd_driver.get_devices()
        for nic in self.nics_in_node:
            self.verify(
                nic["pci_address"] in dev_list,
                f"Device {nic['pci_address']} was not listed in testpmd's available devices, "
                "please check your configuration",
            )

    def test_device_bound_to_driver(self) -> None:
        """
        Test:
            Ensure that all drivers listed in the config are bound to the correct driver.
        """
        path_to_devbind = self.sut_node.main_session.join_remote_path(
            self.sut_node._remote_dpdk_dir, "usertools", "dpdk-devbind.py"
        )

        regex_for_pci_address = "/[0-9]{4}:[0-9]{2}:[0-9]{2}.[0-9]{1}/"
        all_nics_in_dpdk_devbind = self.sut_node.main_session.send_command(
            f"{path_to_devbind} --status | awk '{regex_for_pci_address}'",
            SETTINGS.timeout,
        ).stdout

        for nic in self.nics_in_node:
            # This regular expression finds the line in the above string that starts
            # with the address for the nic we are on in the loop and then captures the
            # name of the driver in a group
            devbind_info_for_nic = re.search(
                f"{nic['pci_address']}[^\\n]*drv=([\\d\\w]*) [^\\n]*",
                all_nics_in_dpdk_devbind,
            )
            self.verify(
                devbind_info_for_nic is not None,
                f"Failed to find configured device ({nic['pci_address']}) using dpdk-devbind.py",
            )
            # We know this isn't None, but mypy doesn't
            assert devbind_info_for_nic is not None
            self.verify(
                devbind_info_for_nic.group(1) == nic["current_driver"],
                f"Driver for device {nic['pci_address']} does not match driver listed in "
                f"configuration (bound to {devbind_info_for_nic.group(1)})",
            )
