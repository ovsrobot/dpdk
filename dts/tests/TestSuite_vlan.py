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

from scapy.layers.l2 import Dot1Q, Ether  # type: ignore[import-untyped]
from scapy.packet import Raw  # type: ignore[import-untyped]

from framework.remote_session.testpmd_shell import SimpleForwardingModes, TestPmdShell
from framework.test_suite import TestSuite


class TestVlan(TestSuite):
    """DPDK VLAN test suite.

    Ensures VLAN packet reception, stripping, and insertion on the Poll Mode Driver
    when the appropriate conditions are met. The suite contains four test cases:

    1. VLAN reception no stripping - verifies that a vlan packet with a tag
    within the filter list is received.
    2. VLAN reception stripping - verifies that a vlan packet with a tag
    within the filter list is received without the vlan tag.
    3. VLAN no reception - verifies that a vlan packet with a tag not within
    the filter list is dropped.
    4. VLAN insertion - verifies that a non vlan packet is received with a vlan
    tag when insertion is enabled.
    """

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Verify that at least two ports are open for session.
        """
        self.verify(len(self._port_links) > 1, "Not enough ports")

    def send_vlan_packet_and_verify(self, should_receive: bool, strip: bool, vlan_id: int) -> None:
        """Generate a vlan packet, send and verify packet with same payload is received on the dut.

        Args:
            should_receive: Indicate whether the packet should be successfully received.
            strip: Indicates whether stripping is on or off, and when the vlan tag is
                checked for a match.
            vlan_id: Expected vlan ID.
        """
        packet = Ether() / Dot1Q(vlan=vlan_id) / Raw(load="xxxxx")
        received_packets = self.send_packet_and_capture(packet)
        test_packet = None
        for packet in received_packets:
            if b"xxxxx" in packet.load:
                test_packet = packet
                break
        if should_receive:
            self.verify(
                test_packet is not None, "Packet was dropped when it should have been received"
            )
            if test_packet is not None:
                if strip:
                    self.verify(
                        not test_packet.haslayer(Dot1Q), "Vlan tag was not stripped successfully"
                    )
                else:
                    self.verify(
                        test_packet.vlan == vlan_id,
                        "The received tag did not match the expected tag",
                    )
        else:
            self.verify(
                test_packet is None,
                "Packet was received when it should have been dropped",
            )

    def send_packet_and_verify_insertion(self, expected_id: int) -> None:
        """Generate a packet with no vlan tag, send and verify on the dut.

        Args:
            expected_id: The vlan id that is being inserted through tx_offload configuration.
        """
        packet = Ether() / Raw(load="xxxxx")
        received_packets = self.send_packet_and_capture(packet)
        test_packet = None
        for packet in received_packets:
            if b"xxxxx" in packet.load:
                test_packet = packet
                break
        self.verify(test_packet is not None, "Packet was dropped when it should have been received")
        if test_packet is not None:
            self.verify(test_packet.haslayer(Dot1Q), "The received packet did not have a vlan tag")
            self.verify(
                test_packet.vlan == expected_id, "The received tag did not match the expected tag"
            )

    def vlan_setup(self, testpmd: TestPmdShell, port_id: int, filtered_id: int) -> TestPmdShell:
        """Setup method for all test cases.

        Args:
            testpmd: Testpmd shell session to send commands to.
            port_id: Number of port to use for setup.
            filtered_id: ID to be added to the vlan filter list.

        Returns:
            TestPmdShell: Testpmd session being configured.
        """
        testpmd.set_forward_mode(SimpleForwardingModes.mac)
        testpmd.set_promisc(port_id, False)
        testpmd.vlan_filter_set(port=port_id, on=True)
        testpmd.rx_vlan(vlan=filtered_id, port=port_id, add=True)
        return testpmd

    def test_vlan_receipt_no_stripping(self) -> None:
        """Ensure vlan packet is dropped when receipts are enabled and header stripping is disabled.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        with TestPmdShell(node=self.sut_node) as testpmd:
            testpmd = self.vlan_setup(testpmd=testpmd, port_id=0, filtered_id=1)
            testpmd.start()
            self.send_vlan_packet_and_verify(True, strip=False, vlan_id=1)

    def test_vlan_receipt_stripping(self) -> None:
        """Ensure vlan packet received with no tag when receipts and header stripping are enabled.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        with TestPmdShell(node=self.sut_node) as testpmd:
            testpmd = self.vlan_setup(testpmd=testpmd, port_id=0, filtered_id=1)
            testpmd.vlan_strip_set(port=0, on=True)
            testpmd.start()
            self.send_vlan_packet_and_verify(should_receive=True, strip=True, vlan_id=1)

    def test_vlan_no_receipt(self) -> None:
        """Ensure vlan packet dropped when filter is on and sent tag not in the filter list.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        with TestPmdShell(node=self.sut_node) as testpmd:
            testpmd = self.vlan_setup(testpmd=testpmd, port_id=0, filtered_id=1)
            testpmd.start()
            self.send_vlan_packet_and_verify(should_receive=False, strip=False, vlan_id=2)

    def test_vlan_header_insertion(self) -> None:
        """Ensure that vlan packet is received with the correct inserted vlan tag.

        Test:
            Create an interactive testpmd shell and verify a non-vlan packet.
        """
        with TestPmdShell(node=self.sut_node) as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.mac)
            testpmd.set_promisc(port=0, on=False)
            testpmd.port_stop_all()
            testpmd.tx_vlan_set(port=1, vlan=51)
            testpmd.port_start_all()
            testpmd.start()
            self.send_packet_and_verify_insertion(expected_id=51)
