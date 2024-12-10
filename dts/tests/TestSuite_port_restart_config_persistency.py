# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

"""Port config persistency Test suite.

Changes configuration of ports and verifies that the configuration persists after a
port is restarted.
"""

from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite, func_test
from framework.testbed_model.capability import NicCapability, requires

ALTERNATIVE_MTU: int = 800
STANDARD_MTU: int = 1500
ALTERNATITVE_MAC_ADDRESS: str = "40:A6:B7:9E:B4:81"


class TestPortRestartConfigPersistency(TestSuite):
    """Port config persistency Test suite."""

    def restart_port_and_verify(self, id, testpmd, changed_value) -> None:
        """Fetches all of the port configs, restarts all of the ports, fetches all the port
        configs again and then compares the two the configs and varifies that they are the same.
        """

        testpmd.start_all_ports()
        testpmd.wait_link_status_up(port_id=id, timeout=10)

        port_info_before = testpmd.show_port_info(id)
        all_info_before = port_info_before.__dict__
        try:
            flow_info_before = testpmd.show_port_flow_info(id)
            all_info_before.update(flow_info_before.__dict__)
        except:
            pass

        testpmd.stop_all_ports()
        testpmd.start_all_ports()
        testpmd.wait_link_status_up(port_id=id, timeout=10)

        port_info_after = testpmd.show_port_info(id)
        all_info_after = port_info_after.__dict__
        try:
            flow_info_after = testpmd.show_port_flow_info(id)
            all_info_after.update(flow_info_after.__dict__)
        except:
            pass

        self.verify(
            all_info_before == all_info_after,
            f"Port configuration for {changed_value} was not retained through port restart",
        )
        testpmd.stop_all_ports()

    @func_test
    def port_configuration_persistence(self) -> None:
        """Port restart configuration Persistency Test.

        Steps:
            For each port set the port MTU, VLAN Filter, Mac Address, VF mode, and Promiscuous Mode.

        Verify:
            Check that the configuration persists after the port is restarted.
        """

        with TestPmdShell(self.sut_node) as testpmd:
            testpmd.stop_all_ports()
            all_ports = [port.id for port in testpmd.show_port_info_all()]
            for port_id in all_ports:
                testpmd.set_port_mtu(port_id=port_id, mtu=STANDARD_MTU, verify=True)

                self.restart_port_and_verify(port_id, testpmd, "mtu")

                testpmd.set_port_mtu(port_id=port_id, mtu=ALTERNATIVE_MTU, verify=True)

                self.restart_port_and_verify(port_id, testpmd, "mtu")

                testpmd.set_vlan_filter(port=port_id, enable=True, verify=True)

                self.restart_port_and_verify(port_id, testpmd, "VLAN_filter")

                testpmd.set_mac_address(port=port_id, mac_address=ALTERNATITVE_MAC_ADDRESS)

                self.restart_port_and_verify(port_id, testpmd, "mac_address")

                testpmd.set_port_VF_mode(port=port_id, vf_id=port_id, rxmode="AUPE", enable=True)

                self.restart_port_and_verify(port_id, testpmd, "VF_mode")

                testpmd.set_promisc(port=port_id, enable=True, verify=False)

                self.restart_port_and_verify(port_id, testpmd, "Promiscuous_Mode")

    @requires(NicCapability.FLOW_CTRL)
    @func_test
    def flow_ctrl_port_configuration_persistence(self) -> None:
        """Flow Control port restart configuration Persistency Test.

        Steps:
            For each port enable flow control for RX and TX individualy.
        Verify:
            Check that the configuration persists after the port is restarted.
        """

        with TestPmdShell(self.sut_node) as testpmd:
            testpmd.stop_all_ports()
            all_ports = [port.id for port in testpmd.show_port_info_all()]
            for port_id in all_ports:

                testpmd.set_flow_control(port=port_id, rx=True, tx=False)

                self.restart_port_and_verify(port_id, testpmd, "flow_ctrl")

                testpmd.set_flow_control(port=port_id, rx=False, tx=True)

                self.restart_port_and_verify(port_id, testpmd, "flow_ctrl")
