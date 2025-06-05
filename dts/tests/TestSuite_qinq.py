# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""QinQ (802.1ad) Test Suite.

This test suite verifies the correctness and capability of DPDK Poll Mode Drivers (PMDs)
in handling QinQ-tagged Ethernet frames, which contain a pair of stacked VLAN headers
(outer S-VLAN and inner C-VLAN). These tests ensure that both software and hardware offloads
related to QinQ behave as expected across different NIC vendors and PMD implementations.

"""

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Packet

from framework.params.testpmd import SimpleForwardingModes
from framework.remote_session.testpmd_shell import PacketOffloadFlag, TestPmdShell
from framework.test_suite import TestSuite, func_test
from framework.testbed_model.capability import NicCapability, TopologyType, requires


@requires(topology_type=TopologyType.two_links)
@requires(NicCapability.RX_OFFLOAD_VLAN_FILTER)
@requires(NicCapability.RX_OFFLOAD_VLAN_EXTEND)
class TestQinq(TestSuite):
    """QinQ test suite.

    This suite consists of 3 test cases:
    1. QinQ Rx parse: Ensures correct classification and detection of double VLAN packets (QinQ).
    2. QinQ strip: Validates hardware offload of VLAN header removal and correct TCI population.
    3. QinQ filter:

    """

    def send_packet_and_verify_offload_flags(
        self, packet: Packet, testpmd: TestPmdShell, offload_flags: list[PacketOffloadFlag]
    ) -> None:
        """Send packet and verify offload flags match the stripping action.

        Args:
            packet: The packet to send to testpmd.
            testpmd: The testpmd session to send commands to.
            offload_flags: List of PacketOffloadFlags that should be in verbose output.
        """
        testpmd.start()
        self.send_packet_and_capture(packet=packet)
        verbose_output = testpmd.extract_verbose_output(testpmd.stop())
        for flag in offload_flags:
            self.verify(flag in verbose_output, f"Expected flag {flag} not found in output")

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

    @property
    def test_packet(self):
        """QinQ packet to be used in each test case."""
        return (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / Dot1Q(vlan=100, type=0x8100)
            / Dot1Q(vlan=200)
            / IP(dst="1.2.3.4")
            / UDP(dport=1234, sport=4321)
        )

    @func_test
    def test_qinq_rx_parse(self) -> None:
        """QinQ Rx parse test case.

        Steps:
            Launch testpmd with Rxonly forwarding mode.
            Set verbose level to 1.
            Enable VLAN filter/extend modes on port 0.
            Send test packet and capture verbose output.

        Verify:
            Check that all expected offload flags are in verbose output.
        """
        offload_flags = [PacketOffloadFlag.RTE_MBUF_F_RX_QINQ, PacketOffloadFlag.RTE_MBUF_F_RX_VLAN]
        with TestPmdShell(forward_mode=SimpleForwardingModes.rxonly) as testpmd:
            testpmd.set_verbose(level=1)
            testpmd.stop_all_ports()
            testpmd.set_vlan_filter(0, True)
            testpmd.set_vlan_extend(0, True)
            testpmd.start_all_ports()
            self.send_packet_and_verify_offload_flags(self.test_packet, testpmd, offload_flags)

    @requires(NicCapability.RX_OFFLOAD_QINQ_STRIP)
    @func_test
    def test_qinq_strip(self) -> None:
        """QinQ Rx strip test case.

        Steps:
            Launch testpmd with Rxonly forwarding mode.
            Set verbose level to 1.
            Enable VLAN filter/extend modes on port 0.
            Enable QinQ strip mode on port 0.
            Send test packet and capture verbose output.

        Verify:
            Check that all expected offload flags are in verbose output.
        """
        offload_flags = [
            PacketOffloadFlag.RTE_MBUF_F_RX_QINQ_STRIPPED,
            PacketOffloadFlag.RTE_MBUF_F_RX_VLAN_STRIPPED,
            PacketOffloadFlag.RTE_MBUF_F_RX_VLAN,
            PacketOffloadFlag.RTE_MBUF_F_RX_QINQ,
        ]
        with TestPmdShell(forward_mode=SimpleForwardingModes.rxonly) as testpmd:
            testpmd.set_verbose(level=1)
            testpmd.stop_all_ports()
            testpmd.set_vlan_filter(0, True)
            testpmd.set_vlan_extend(0, True)
            testpmd.set_qinq_strip(0, True)
            testpmd.start_all_ports()
            self.send_packet_and_verify_offload_flags(self.test_packet, testpmd, offload_flags)

    @func_test
    def test_qinq_filter(self) -> None:
        """QinQ Rx filter test case.

        Steps:
            Launch testpmd with Rxonly forwarding mode.
            Enable VLAN filter/extend modes on port 0.
            Add VLAN tag 100 to the filter on port 0.
            Send test packet and capture verbose output.

        Verify:
            Check that all expected offload flags are in verbose output.
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
        with TestPmdShell(forward_mode=SimpleForwardingModes.rxonly) as testpmd:
            testpmd.stop_all_ports()
            testpmd.set_vlan_filter(0, True)
            testpmd.set_vlan_extend(0, True)
            testpmd.start_all_ports()
            testpmd.rx_vlan(100, 0)
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
        with TestPmdShell(forward_mode=SimpleForwardingModes.mac) as testpmd:
            testpmd.stop_all_ports()
            testpmd.set_vlan_filter(0, False)
            testpmd.start_all_ports()
            received_packet = self.send_packet_and_capture(self.test_packet)
            for packet in received_packet:
                vlan_tags = [layer for layer in packet.layers() if layer == Dot1Q]
                self.verify(len(vlan_tags) == 2, f"Expected 2 VLAN tags, found {len(vlan_tags)}")

                if packet.haslayer(Dot1Q):
                    outer_vlan_id = packet[Dot1Q].vlan
                    self.verify(
                        outer_vlan_id == 100,
                        f"Outer VLAN ID was {outer_vlan_id} when it should have been 100.",
                    )

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
            Launch testpmd in rxonly forward mode.
            Set verbose level to 1.
            Disable VLAN filtering on port 0.
            Send and capture test packet.

        Verify:
            Only 1 VLAN tag is in received packet.
            Inner VLAN ID matches the original packet.
        """
        with TestPmdShell(forward_mode=SimpleForwardingModes.rxonly) as testpmd:
            testpmd.set_verbose(level=1)
            testpmd.stop_all_ports()
            testpmd.set_vlan_filter(0, False)
            testpmd.start_all_ports()

            mismatched_packet = (
                Ether(dst="ff:ff:ff:ff:ff:ff")
                / Dot1Q(vlan=100, type=0x1234)
                / Dot1Q(vlan=200)
                / IP(dst="1.2.3.4")
                / UDP(dport=1234, sport=4321)
            )

            received_packet = self.send_packet_and_capture(mismatched_packet)

            for packet in received_packet:
                vlan_tags = [layer for layer in packet.layers() if layer == Dot1Q]
                self.verify(
                    len(vlan_tags) == 1,
                    f"Expected 1 VLAN tag due to mismatched TPID, found {len(vlan_tags)}",
                )

                vlan_id = packet[Dot1Q].vlan
                self.verify(vlan_id == 200, f"Expected inner VLAN ID 200, got {vlan_id}")
