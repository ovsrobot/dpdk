# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 University of New Hampshire

"""Test the support of VLAN Offload Features by Poll Mode Drivers.

The test suite ensures that with the correct configuration, a port
will not drop a VLAN tagged packet. In order for this to be successful,
packet header stripping and packet receipts must be enabled on the Poll Mode Driver.
The test suite checks that when these conditions are met, the packet is received without issue.
The suite also checks to ensure that when these conditions are not met, as in the cases where
stripping is disabled, or VLAN packet receipts are disabled, the packet is not received.
Additionally, it checks the case where VLAN header insertion is enabled in transmitted packets,
which should be successful if the previous cases pass.

"""

from scapy.layers.l2 import Dot1Q, Ether  # type: ignore[import]
from scapy.packet import Raw  # type: ignore[import]

from framework.remote_session.testpmd_shell import TestPmdForwardingModes, TestPmdShell
from framework.test_suite import TestSuite


class TestVlan(TestSuite):
    """DPDK VLAN test suite.

    Ensures VLAN packet reception on the Poll Mode Driver when certain conditions are met.
    If one or more of these conditions are not met, the packet reception should be unsuccessful.
    """

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Create a testpmd session and set up tg nodes
            verify that at least two ports are open for session
        """
        self.verify(len(self._port_links) > 1, "Not enough ports")

    def send_vlan_packet_and_verify(
        self, should_receive: bool = True, strip: bool = False, vlan_id: int = -1
    ) -> None:
        """Generate a vlan packet, send and verify on the dut.

        Args:
            should_receive: indicate whether the packet should be successfully received
            vlan_id: expected vlan ID
            strip: indicates whether stripping is on or off,
            and when the vlan tag is checked for a match
        """
        data = "P" * 10
        packet = Ether() / Dot1Q(vlan=vlan_id) / Raw(load=data)
        received_packets = self.send_packet_and_capture(packet)
        received_packets = [
            packets
            for packets in received_packets
            if hasattr(packets, "load") and data in str((packets.load))
        ]
        if should_receive:
            self.verify(
                len(received_packets) == 1, "Packet was dropped when it should have been received"
            )
            received = received_packets[0]
            if strip:
                self.verify(Dot1Q not in received, "Vlan tag was not stripped successfully")
            else:
                if len(received_packets) == 1:
                    self.verify(
                        received.vlan == vlan_id, "The received tag did not match the expected tag"
                    )
        else:
            self.verify(
                not len(received_packets) == 1,
                "Packet was received when it should have been dropped",
            )

    def send_packet_and_verify_insertion(self, expected_id: int = -1) -> None:
        """Generate a packet with no vlan tag, send and verify on the dut.

        Args:
            expected_id: the vlan id that is being inserted through tx_offload configuration
            should_receive: indicate whether the packet should be successfully received
        """
        data = "P" * 10
        packet = Ether() / Raw(load=data)
        received_packets = self.send_packet_and_capture(packet)
        received_packets = [
            packets
            for packets in received_packets
            if hasattr(packets, "load") and data in str((packets.load))
        ]
        self.verify(
            len(received_packets) == 1, "Packet was dropped when it should have been received"
        )
        received = received_packets[0]
        self.verify(Dot1Q in received, "The received packet did not have a vlan tag")
        self.verify(received.vlan == expected_id, "The received tag did not match the expected tag")

    def test_vlan_receipt_no_stripping(self) -> None:
        """Ensure vlan packet is dropped when receipts are enabled and header stripping is disabled.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        testpmd = self.sut_node.create_interactive_shell(TestPmdShell, privileged=True)
        testpmd.set_forward_mode(TestPmdForwardingModes.mac)
        testpmd.send_command("set verbose 1", "testpmd>")
        testpmd.send_command("set promisc 0 off", "testpmd>")
        testpmd.send_command("vlan set filter on 0", "testpmd>")
        testpmd.send_command("rx_vlan add 1 0", "testpmd>")
        testpmd.start()

        filtered_vlan = 1
        self.send_vlan_packet_and_verify(True, vlan_id=filtered_vlan)
        testpmd.close()

    def test_vlan_receipt_stripping(self) -> None:
        """Ensure vlan packet received with no tag when receipts and header stripping are enabled.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        testpmd = self.sut_node.create_interactive_shell(TestPmdShell, privileged=True)
        testpmd.set_forward_mode(TestPmdForwardingModes.mac)
        testpmd.send_command("set verbose 1", "testpmd>")
        testpmd.send_command("set promisc 0 off", "testpmd>")
        testpmd.send_command("vlan set filter on 0", "testpmd>")
        testpmd.send_command("rx_vlan add 1 0", "testpmd>")
        testpmd.send_command("vlan set strip on 0", "testpmd>")
        testpmd.start()

        self.send_vlan_packet_and_verify(should_receive=True, strip=True, vlan_id=1)
        testpmd.close()

    def test_vlan_no_receipt(self) -> None:
        """Ensure vlan packet dropped when filter is on and sent tag not in the filter list.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        testpmd = self.sut_node.create_interactive_shell(TestPmdShell, privileged=True)
        testpmd.set_forward_mode(TestPmdForwardingModes.mac)
        testpmd.send_command("set verbose 1", "testpmd>")
        testpmd.send_command("set promisc 0 off", "testpmd>")
        testpmd.send_command("vlan set filter on 0", "testpmd>")
        testpmd.send_command("rx_vlan add 1 0", "testpmd>")
        testpmd.start()

        filtered_vlan = 1
        self.send_vlan_packet_and_verify(should_receive=False, vlan_id=filtered_vlan + 1)
        testpmd.close()

    def test_vlan_header_insertion(self) -> None:
        """Ensure that vlan packet is received with the correct inserted vlan tag.

        Test:
            Create an interactive testpmd shell and verify a non-vlan packet.
        """
        testpmd = self.sut_node.create_interactive_shell(TestPmdShell, privileged=True)
        testpmd.set_forward_mode(TestPmdForwardingModes.mac)
        testpmd.send_command("set verbose 1", "testpmd>")
        testpmd.send_command("set promisc 0 off", "testpmd>")
        testpmd.send_command("port stop all", "testpmd>")
        testpmd.send_command("tx_vlan set 1 51", "testpmd>")
        testpmd.send_command("port start all", "testpmd>")
        testpmd.start()

        self.send_packet_and_verify_insertion(expected_id=51)
        testpmd.close()

    def tear_down_suite(self) -> None:
        """Tear down the suite."""
