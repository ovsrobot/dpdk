# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire

"""Smoke test suite.

Smoke tests are a class of tests which are used for validating a minimal set of important features.
These are the most important features without which (or when they're faulty) the software wouldn't
work properly. Thus, if any failure occurs while testing these features,
there isn't that much of a reason to continue testing, as the software is fundamentally broken.

These tests don't have to include only DPDK tests, as the reason for failures could be
in the infrastructure (a faulty link between NICs or a misconfiguration).
"""

import re

from framework.config import PortConfig
from framework.remote_session import TestPmdShell
from framework.settings import SETTINGS
from framework.test_suite import TestSuite
from framework.utils import REGEX_FOR_PCI_ADDRESS


class SmokeTests(TestSuite):
    """DPDK and infrastructure smoke test suite.

    The test cases validate the most basic DPDK functionality needed for all other test suites.
    The infrastructure also needs to be tested, as that is also used by all other test suites.

    Attributes:
        is_blocking: This test suite will block the execution of all other test suites
            in the build target after it.
        nics_in_node: The NICs present on the SUT node.
    """

    is_blocking = True
    # dicts in this list are expected to have two keys:
    # "pci_address" and "current_driver"
    nics_in_node: list[PortConfig] = []

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Set the build directory path and generate a list of NICs in the SUT node.
        """
        self.dpdk_build_dir_path = self.sut_node.remote_dpdk_build_dir
        self.nics_in_node = self.sut_node.config.ports

    def test_unit_tests(self) -> None:
        """DPDK meson fast-tests unit tests.

        The DPDK unit tests are basic tests that indicate regressions and other critical failures.
        These need to be addressed before other testing.

        The fast-tests unit tests are a subset with only the most basic tests.

        Test:
            Run the fast-test unit-test suite through meson.
        """
        self.sut_node.main_session.send_command(
            f"meson test -C {self.dpdk_build_dir_path} --suite fast-tests -t 60",
            480,
            verify=True,
            privileged=True,
        )

    def test_driver_tests(self) -> None:
        """DPDK meson driver-tests unit tests.

        The DPDK unit tests are basic tests that indicate regressions and other critical failures.
        These need to be addressed before other testing.

        The driver-tests unit tests are a subset that test only drivers. These may be run
        with virtual devices as well.

        Test:
            Run the driver-test unit-test suite through meson.
        """
        vdev_args = ""
        for dev in self.sut_node.virtual_devices:
            vdev_args += f"--vdev {dev} "
        vdev_args = vdev_args[:-1]
        driver_tests_command = (
            f"meson test -C {self.dpdk_build_dir_path} --suite driver-tests"
        )
        if vdev_args:
            self._logger.info(
                "Running driver tests with the following virtual "
                f"devices: {vdev_args}"
            )
            driver_tests_command += f' --test-args "{vdev_args}"'

        self.sut_node.main_session.send_command(
            driver_tests_command,
            300,
            verify=True,
            privileged=True,
        )

    def test_devices_listed_in_testpmd(self) -> None:
        """Testpmd device discovery.

        If the configured devices can't be found in testpmd, they can't be tested.

        Test:
            Uses testpmd driver to verify that devices have been found by testpmd.
        """
        testpmd_driver = self.sut_node.create_interactive_shell(
            TestPmdShell, privileged=True
        )
        dev_list = [str(x) for x in testpmd_driver.get_devices()]
        for nic in self.nics_in_node:
            self.verify(
                nic.pci in dev_list,
                f"Device {nic.pci} was not listed in testpmd's available devices, "
                "please check your configuration",
            )

    def test_device_bound_to_driver(self) -> None:
        """Device driver in OS.

        The devices must be bound to the proper driver, otherwise they can't be used by DPDK
        or the traffic generators.

        Test:
            Ensure that all drivers listed in the config are bound to the correct
            driver.
        """
        path_to_devbind = self.sut_node.path_to_devbind_script

        all_nics_in_dpdk_devbind = self.sut_node.main_session.send_command(
            f"{path_to_devbind} --status | awk '{REGEX_FOR_PCI_ADDRESS}'",
            SETTINGS.timeout,
        ).stdout

        for nic in self.nics_in_node:
            # This regular expression finds the line in the above string that starts
            # with the address for the nic we are on in the loop and then captures the
            # name of the driver in a group
            devbind_info_for_nic = re.search(
                f"{nic.pci}[^\\n]*drv=([\\d\\w]*) [^\\n]*",
                all_nics_in_dpdk_devbind,
            )
            self.verify(
                devbind_info_for_nic is not None,
                f"Failed to find configured device ({nic.pci}) using dpdk-devbind.py",
            )
            # We know this isn't None, but mypy doesn't
            assert devbind_info_for_nic is not None
            self.verify(
                devbind_info_for_nic.group(1) == nic.os_driver_for_dpdk,
                f"Driver for device {nic.pci} does not match driver listed in "
                f"configuration (bound to {devbind_info_for_nic.group(1)})",
            )
