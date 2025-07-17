# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""QinQ (802.1ad) Test Suite.

This test suite verifies the correctness and capability of DPDK Poll Mode Drivers (PMDs)
in handling QinQ-tagged Ethernet frames, which contain a pair of stacked VLAN headers
(outer S-VLAN and inner C-VLAN). These tests ensure that both software and hardware offloads
related to QinQ behave as expected across different NIC vendors and PMD implementations.

"""

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Dot1AD, Dot1Q, Ether
from scapy.packet import Packet

from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite, func_test
from framework.testbed_model.capability import NicCapability, requires


class TestQinq(TestSuite):
    """QinQ test suite.

    This suite consists of 4 test cases:
    1. QinQ Filter: Enable VLAN filter and verify packets with mismatched VLAN IDs are dropped,
        and packets with matching VLAN IDs are received.
    2. QinQ Forwarding: Send a QinQ packet and verify the received packet contains
        both QinQ/VLAN layers.
    3. Mismatched TPID: Send a Qinq packet with an invalid TPID (not 0x8100/0x88a8) and verify the
        mismatched VLAN layer is interpreted as part of the Ethertype (expected DPDK behavior.)
    4. VLAN Strip: Enable VLAN stripping and verify sent packets are received with the
        expected VLAN/QinQ layers.
    5. QinQ Strip: Enable VLAN/QinQ stripping and verify sent packets are received with the
        expected VLAN/QinQ layers.
    """

    def send_packet_and_verify(
        self, packet: Packet, testpmd: TestPmdShell, should_receive: bool
    ) -> None:
        """Send packet and verify reception.

        Args:
            packet: The packet to send to testpmd.
            testpmd: The testpmd session to send commands to.
            should_receive: If :data:`True`, verifies packet was received.
        """
        testpmd.start()
        received = self.send_packet_and_capture(packet=packet)
        if should_receive:
            self.verify(received != [], "Packet was dropped when it should have been received.")
        else:
            self.verify(received == [], "Packet was received when it should have been dropped.")

    @requires(NicCapability.RX_OFFLOAD_VLAN_EXTEND)
    @func_test
    def test_qinq_filter(self) -> None:
        """QinQ Rx filter test case.

        Steps:
            Launch testpmd with mac forwarding mode.
            Enable VLAN filter/extend modes on port 0.
            Add VLAN tag 100 to the filter on port 0.
            Send test packet and capture verbose output.

        Verify:
            Packet with matching VLAN ID is received.
            Packet with mismatched VLAN ID is dropped.
        """
        packets = [
            Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
            / Dot1Q(vlan=100)
            / Dot1Q(vlan=200)
            / IP(dst="192.0.2.1", src="198.51.100.1")
            / UDP(dport=1234, sport=5678),
            Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
            / Dot1Q(vlan=101)
            / Dot1Q(vlan=200)
            / IP(dst="192.0.2.1", src="198.51.100.1")
            / UDP(dport=1234, sport=5678),
        ]
        with TestPmdShell() as testpmd:
            testpmd.stop_all_ports()
            testpmd.set_vlan_filter(0, True)
            testpmd.set_vlan_extend(0, True)
            testpmd.start_all_ports()
            testpmd.rx_vlan(100, 0, True)
            self.send_packet_and_verify(packets[0], testpmd, should_receive=True)
            self.send_packet_and_verify(packets[1], testpmd, should_receive=False)

    @func_test
    def test_qinq_forwarding(self) -> None:
        """QinQ Rx filter test case.

        Steps:
            Launch testpmd with mac forwarding mode.
            Disable VLAN filter mode on port 0.
            Send test packet and capture verbose output.

        Verify:
            Check that the received packet has two separate VLAN layers in proper QinQ fashion.
            Check that the received packet outer and inner VLAN layer has the appropriate ID.
        """
        test_packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / Dot1AD(vlan=100)
            / Dot1Q(vlan=200)
            / IP(dst="1.2.3.4")
            / UDP(dport=1234, sport=4321)
        )
        with TestPmdShell() as testpmd:
            testpmd.stop_all_ports()
            testpmd.set_vlan_filter(0, False)
            testpmd.start_all_ports()
            testpmd.start()
            received_packet = self.send_packet_and_capture(test_packet)

            self.verify(
                received_packet != [], "Packet was dropped when it should have been received."
            )

            for packet in received_packet:
                vlan_tags = packet.getlayer(Dot1AD), packet.getlayer(Dot1Q)
                self.verify(len(vlan_tags) == 2, f"Expected 2 VLAN tags, found {len(vlan_tags)}")

                if packet.haslayer(Dot1Q):
                    outer_vlan_id = packet[Dot1Q].vlan
                    self.verify(
                        outer_vlan_id == 100,
                        f"Outer VLAN ID was {outer_vlan_id} when it should have been 100.",
                    )
                else:
                    self.verify(False, "VLAN layer not found in received packet.")

                if packet[Dot1Q].haslayer(Dot1Q):
                    inner_vlan_id = packet[Dot1Q].payload[Dot1Q].vlan
                    self.verify(
                        inner_vlan_id == 200,
                        f"Inner VLAN ID was {inner_vlan_id} when it should have been 200",
                    )

    @func_test
    def test_mismatched_tpid(self) -> None:
        """Test behavior when outer VLAN tag has a non-standard TPID (not 0x8100 or 0x88a8).

        Steps:
            Launch testpmd in mac forward mode.
            Set verbose level to 1.
            Disable VLAN filtering on port 0.
            Send and capture test packet.

        Verify:
            Only 1 VLAN tag is in received packet.
            Inner VLAN ID matches the original packet.
        """
        with TestPmdShell() as testpmd:
            testpmd.set_verbose(level=1)
            testpmd.stop_all_ports()
            testpmd.set_vlan_filter(0, False)
            testpmd.start_all_ports()
            testpmd.start()

            mismatched_packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff")
                / Dot1Q(vlan=100, type=0x1234)
                / Dot1Q(vlan=200)
                / IP(dst="1.2.3.4")
                / UDP(dport=1234, sport=4321)
            )

            received_packet = self.send_packet_and_capture(mismatched_packet)

            self.verify(
                received_packet != [], "Packet was dropped when it should have been received."
            )

            for packet in received_packet:
                vlan_tags = [layer for layer in packet.layers() if layer == Dot1Q]
                self.verify(
                    len(vlan_tags) == 1,
                    f"Expected 1 VLAN tag due to mismatched TPID, found {len(vlan_tags)}",
                )

                vlan_id = packet[Dot1Q].vlan
                self.verify(vlan_id == 200, f"Expected inner VLAN ID 200, got {vlan_id}")

    def strip_verify(
        self, packet: Packet, expected_num_tags: int, context: str, check_id: bool = False
    ) -> None:
        """Helper method for verifying packet stripping functionality."""
        if expected_num_tags == 0:
            has_vlan = bool(packet.haslayer(Dot1Q))
            if not has_vlan:
                self.verify(True, "Packet contained VLAN layer")
            else:
                vlan_layer = packet.getlayer(Dot1Q)
                self.verify(
                    vlan_layer is not None
                    and vlan_layer.type != 0x8100
                    and vlan_layer.type != 0x88A8,
                    f"""VLAN tags found in packet when should have been stripped: {packet.summary()}
                    sent packet: {context}""",
                )
        if expected_num_tags == 1:

            def count_vlan_tags(packet: Packet) -> int:
                """Method for counting the number of VLAN layers in a packet."""
                count = 0
                layer = packet.getlayer(Dot1Q)
                while layer:
                    if layer.type == 0x8100:
                        count += 1
                    layer = layer.payload.getlayer(Dot1Q)
                return count

            tag_count = count_vlan_tags(packet)
            self.verify(
                tag_count == 1,
                f"""Expected one 0x8100 VLAN tag but found {tag_count}: {packet.summary()}
                sent packet: {context}""",
            )
            first_dot1q = packet.getlayer(Dot1Q)
            self.verify(
                first_dot1q is not None and first_dot1q.type == 0x8100,
                f"""VLAN tag 0x8100 not found in packet: {packet.summary()}
                sent packet: {context}""",
            )
            if check_id:
                self.verify(
                    packet[Dot1Q].vlan == 200,
                    f"""VLAN ID 200 not found in received packet: {packet.summary()}
                    sent packet: {context}""",
                )

    @requires(NicCapability.RX_OFFLOAD_VLAN_STRIP)
    @func_test
    def test_vlan_strip(self) -> None:
        """Test combinations of VLAN/QinQ strip settings with various QinQ packets.

        Steps:
            Launch testpmd with VLAN strip enabled.
            Send four VLAN/QinQ related test packets.

        Verify:
            Check received packets have the expected VLAN/QinQ layers/tags.
        """
        test_packets = [
            Ether() / Dot1Q(type=0x8100) / IP() / UDP(dport=1234, sport=4321),
            Ether()
            / Dot1Q(vlan=100, type=0x8100)
            / Dot1Q(vlan=200, type=0x8100)
            / IP()
            / UDP(dport=1234, sport=4321),
            Ether() / Dot1Q(type=0x88A8) / IP() / UDP(dport=1234, sport=4321),
            Ether() / Dot1Q(type=0x88A8) / Dot1Q(type=0x8100) / IP() / UDP(dport=1234, sport=4321),
        ]
        with TestPmdShell() as testpmd:
            testpmd.stop_all_ports()
            testpmd.set_vlan_strip(0, True)
            testpmd.start_all_ports()
            testpmd.start()

            rec1 = self.send_packet_and_capture(test_packets[0])
            rec2 = self.send_packet_and_capture(test_packets[1])
            rec3 = self.send_packet_and_capture(test_packets[2])
            rec4 = self.send_packet_and_capture(test_packets[3])

            testpmd.stop()

            try:
                context = "Single VLAN"
                self.strip_verify(rec1[0], 0, context)
                context = "Stacked VLAN"
                self.strip_verify(rec2[0], 1, context, check_id=True)
                context = "Single S-VLAN"
                self.strip_verify(rec3[0], 0, context)
                context = "QinQ"
                self.strip_verify(rec4[0], 1, context)
            except IndexError:
                self.verify(
                    False, f"{context} packet was dropped when it should have been received."
                )

    @requires(NicCapability.RX_OFFLOAD_QINQ_STRIP)
    @func_test
    def test_qinq_strip(self) -> None:
        """Test combinations of VLAN/QinQ strip settings with various QinQ packets.

        Steps:
            Launch testpmd with QinQ and VLAN strip enabled.
            Send four VLAN/QinQ related test packets.

        Verify:
            Check received packets have the expected VLAN/QinQ layers/tags.
        """
        test_packets = [
            Ether() / Dot1Q(type=0x8100) / IP() / UDP(dport=1234, sport=4321),
            Ether()
            / Dot1Q(vlan=100, type=0x8100)
            / Dot1Q(vlan=200, type=0x8100)
            / IP()
            / UDP(dport=1234, sport=4321),
            Ether() / Dot1Q(type=0x88A8) / IP() / UDP(dport=1234, sport=4321),
            Ether() / Dot1Q(type=0x88A8) / Dot1Q(type=0x8100) / IP() / UDP(dport=1234, sport=4321),
        ]
        with TestPmdShell() as testpmd:
            testpmd.stop_all_ports()
            testpmd.set_qinq_strip(0, True)
            testpmd.start_all_ports()
            testpmd.start()

            rec1 = self.send_packet_and_capture(test_packets[0])
            rec2 = self.send_packet_and_capture(test_packets[1])
            rec3 = self.send_packet_and_capture(test_packets[2])
            rec4 = self.send_packet_and_capture(test_packets[3])

            testpmd.stop()

            try:
                context = "Single VLAN"
                self.strip_verify(rec1[0], 0, context)
                context = "Stacked VLAN"
                self.strip_verify(rec2[0], 1, context, check_id=True)
                context = "Single S-VLAN"
                self.strip_verify(rec3[0], 0, context)
                context = "QinQ"
                self.strip_verify(rec4[0], 0, context)
            except IndexError:
                self.log(f"{context} packet was dropped when it should have been received.")
