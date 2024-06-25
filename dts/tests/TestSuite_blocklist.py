# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

"""The DPDK device blocklisting test suite.

This testing suite ensures tests the port blocklisting functionality of testpmd.
"""

from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite
from framework.testbed_model.port import Port


class TestBlocklist(TestSuite):
    """DPDK device blocklisting test suite.

    For this test suite to work at least 2 ports need to be configured for the SUT node.
    """

    def set_up_suite(self) -> None:
        """Verify setup."""
        self.verify(len(self.sut_node.ports) >= 2, "At least two ports are required for this test")

    def verify_blocklisted_ports(self, ports_to_block: list[Port]):
        """Runs testpmd with the given ports blocklisted and verifies the ports."""
        testpmd = TestPmdShell(self.sut_node, allowed_ports=[], blocked_ports=ports_to_block)

        allowlisted_ports = {port.device_name for port in testpmd.show_port_info_all()}
        blocklisted_ports = {port.pci for port in ports_to_block}

        # sanity check
        allowed_len = len(allowlisted_ports - blocklisted_ports)
        self.verify(allowed_len > 0, "At least one port should have been allowed")

        blocked = not allowlisted_ports & blocklisted_ports
        self.verify(blocked, "At least one port was not blocklisted")

        testpmd.close()

    def test_bl_no_blocklisted(self):
        """Run testpmd with no blocklisted device.

        Steps:
            Run testpmd without specifying allowed or blocked ports.
        Verify:
            That no ports were blocked.
        """
        self.verify_blocklisted_ports([])

    def test_bl_one_port_blocklisted(self):
        """Run testpmd with one blocklisted port.

        Steps:
            Run testpmd with one only one blocklisted port and allowing all the other ones.
        Verify:
            That the port was successfully blocklisted.
        """
        self.verify_blocklisted_ports(self.sut_node.ports[:1])

    def test_bl_all_but_one_port_blocklisted(self):
        """Run testpmd with all but one blocklisted port.

        Steps:
            Run testpmd with only one allowed port, blocking all the other ones.
        Verify:
            That all specified ports were successfully blocklisted.
        """
        self.verify_blocklisted_ports(self.sut_node.ports[:-1])
