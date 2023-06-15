# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire

from framework.config import InteractiveApp
from framework.remote_session import TestPmdShell
from framework.test_suite import TestSuite


class SmokeTests(TestSuite):
    is_blocking = True
    # in this list, the first index is the address of the nic and the second is
    # the driver for that nic.
    list_of_nics: list[tuple[str, str]] = []

    def set_up_suite(self) -> None:
        """
        Setup:
            build all DPDK
        """
        self.dpdk_build_dir_path = self.sut_node.remote_dpdk_build_dir
        for nic in self.sut_node.config.ports:
            new_tuple = (nic.pci, nic.os_driver.strip())
            self.list_of_nics.append(new_tuple)

    def test_unit_tests(self) -> None:
        """
        Test:
            run the fast-test unit-test suite through meson
        """
        self.sut_node.main_session.send_command(
            f"meson test -C {self.dpdk_build_dir_path} --suite fast-tests",
            300,
            verify=True,
        )

    def test_driver_tests(self) -> None:
        """
        Test:
            run the driver-test unit-test suite through meson
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
            Uses testpmd driver to verify that devices have been found by testpmd
        """
        testpmd_driver: TestPmdShell = self.sut_node.create_interactive_shell(
            InteractiveApp.testpmd
        )
        dev_list: list[str] = testpmd_driver.get_devices()
        for nic in self.list_of_nics:
            self.verify(
                nic[0] in dev_list,
                f"Device {nic[0]} was not listed in testpmd's available devices, "
                "please check your configuration",
            )

    def test_device_bound_to_driver(self) -> None:
        """
        Test:
            ensure that all drivers listed in the config are bound to the correct driver
        """
        path_to_dev = self.sut_node.main_session.join_remote_path(
            self.sut_node._remote_dpdk_dir, "usertools", "dpdk-devbind.py"
        )
        for nic in self.list_of_nics:
            out = self.sut_node.main_session.send_command(
                f"{path_to_dev} --status | grep {nic[0]}", 60
            )
            self.verify(
                len(out.stdout) != 0,
                f"Failed to find configured device ({nic[0]}) using dpdk-devbind.py",
            )
            for string in out.stdout.split(" "):
                if "drv=" in string:
                    self.verify(
                        string.split("=")[1] == nic[1],
                        f"Driver for device {nic[0]} does not match driver listed in "
                        f'configuration (bound to {string.split("=")[1]})',
                    )
