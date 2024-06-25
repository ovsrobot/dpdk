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

from time import sleep
from scapy.layers.l2 import Dot1Q, Ether  # type: ignore[import]
from scapy.packet import Raw  # type: ignore[import]

from framework.remote_session.testpmd_shell import TestPmdShell, SimpleForwardingModes
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

    def send_vlan_packet_and_verify(
        self, should_receive: bool, strip: bool, vlan_id: int
    ) -> None:
        """Generate a vlan packet, send and verify a packet with
        the same payload is received on the dut.

        Args:
            should_receive: Indicate whether the packet should be successfully received.
            vlan_id: Expected vlan ID.
            strip: Indicates whether stripping is on or off, and when the vlan tag is
                checked for a match.
        """
        packet = Ether() / Dot1Q(vlan=vlan_id) / Raw(load='xxxxx')
        received_packets = self.send_packet_and_capture(packet)
        test_packet = None
        for packet in received_packets:
            if b'xxxxx' in packet.load:
                test_packet = packet
                break
        if should_receive:
            self.verify(
                test_packet is not None, "Packet was dropped when it should have been received"
            )
            if strip:
                self.verify(Dot1Q not in test_packet, "Vlan tag was not stripped successfully")
            else:
                    self.verify(
                        test_packet.vlan == vlan_id, "The received tag did not match the expected tag"
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
            should_receive: Indicate whether the packet should be successfully received.
        """
        packet = Ether() / Raw(load='xxxxx')
        received_packets = self.send_packet_and_capture(packet)
        test_packet = None
        for packet in received_packets:
            if b'xxxxx' in packet.load:
                test_packet = packet
                break
        self.verify(
            test_packet is not None, "Packet was dropped when it should have been received"
        )
        self.verify(Dot1Q in test_packet, "The received packet did not have a vlan tag")
        self.verify(test_packet.vlan == expected_id, "The received tag did not match the expected tag")

    def test_vlan_receipt_no_stripping(self) -> None:
        """Ensure vlan packet is dropped when receipts are enabled and header stripping is disabled.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        testpmd = TestPmdShell(node=self.sut_node)
        testpmd.set_forward_mode(SimpleForwardingModes.mac)
        testpmd.set_verbose(1)
        testpmd.set_promisc(0, False)
        testpmd.vlan_filter_set_on(0)
        filtered_vlan = 1
        testpmd.rx_vlan_add(filtered_vlan, 0)
        testpmd.start()

        self.send_vlan_packet_and_verify(True, strip=False, vlan_id=filtered_vlan)
        testpmd.close()
    def test_vlan_receipt_stripping(self) -> None:
        """Ensure vlan packet received with no tag when receipts and header stripping are enabled.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        testpmd = TestPmdShell(node=self.sut_node)
        testpmd.set_forward_mode(SimpleForwardingModes.mac)
        testpmd.set_verbose(1)
        testpmd.set_promisc(0, False)
        testpmd.vlan_filter_set_on(0)
        testpmd.rx_vlan_add(1, 0)
        testpmd.vlan_strip_set_on(0)
        testpmd.start()

        self.send_vlan_packet_and_verify(should_receive=True, strip=True, vlan_id=1)
        testpmd.close()
    def test_vlan_no_receipt(self) -> None:
        """Ensure vlan packet dropped when filter is on and sent tag not in the filter list.

        Test:
            Create an interactive testpmd shell and verify a vlan packet.
        """
        testpmd = TestPmdShell(node=self.sut_node)
        testpmd.set_forward_mode(SimpleForwardingModes.mac)
        testpmd.set_verbose(1)
        testpmd.set_promisc(0, False)
        testpmd.vlan_filter_set_on(0)
        filtered_vlan = 1
        testpmd.rx_vlan_add(filtered_vlan, 0)
        testpmd.start()

        self.send_vlan_packet_and_verify(should_receive=False, strip=False, vlan_id=filtered_vlan + 1)
        testpmd.close()

    def test_vlan_header_insertion(self) -> None:
        """Ensure that vlan packet is received with the correct inserted vlan tag.

        Test:
            Create an interactive testpmd shell and verify a non-vlan packet.
        """
        testpmd = TestPmdShell(node=self.sut_node)
        testpmd.set_forward_mode(SimpleForwardingModes.mac)
        testpmd.set_verbose(1)
        testpmd.set_promisc(0, False)
        testpmd.port_stop_all()
        testpmd.tx_vlan_set(1, 51)
        testpmd.port_start_all()
        testpmd.start()

        self.send_packet_and_verify_insertion(expected_id=51)
        testpmd.close()
