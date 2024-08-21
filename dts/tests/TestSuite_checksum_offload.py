# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 University of New Hampshire

"""DPDK checksum offload testing suite.

This suite verifies L3/L4 checksum offload features of the Poll Mode Driver.
On the Rx side, IPv4 and UDP/TCP checksum by hardware is checked to ensure
checksum flags match expected flags. On the Tx side, IPv4/UDP, IPv4/TCP,
IPv6/UDP, and IPv6/TCP insertion by hardware is checked to checksum flags
match expected flags.

"""

from typing import List

from scapy.all import Packet  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]
from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
from scapy.layers.sctp import SCTP  # type: ignore[import-untyped]
from scapy.layers.l2 import Dot1Q  # type: ignore[import-untyped]
from scapy.layers.l2 import Ether
from scapy.packet import Raw  # type: ignore[import-untyped]

from framework.remote_session.testpmd_shell import (
    SimpleForwardingModes,
    TestPmdShell,
    OLFlag,
    ChecksumOffloadOptions
)
from framework.test_suite import TestSuite


class TestChecksumOffload(TestSuite):
    """Checksum offload test suite.

    This suite consists of 6 test cases:
    1. Insert checksum on transmit packet
    2. Do not insert checksum on transmit packet
    3. Validate Rx checksum valid flags
    4. Hardware checksum check L4 Rx
    5. Hardware checksum check L3 Rx
    6. Checksum offload with vlan

    """

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Verify that at least two port links are created when the
            test run is initialized.
        """
        self.verify(len(self._port_links) > 1, "Not enough port links.")

    def send_packets_and_verify(
        self, packet_list: List[Packet], load: str, should_receive: bool
    ) -> None:
        """Send and verify packet is received on the traffic generator.

        Args:
            packet_list: list of Scapy packets to send and verify.
            load: Raw layer load attribute in the sent packet.
            should_receive: Indicates whether the packet should be received
                by the traffic generator.
        """
        for i in range(0, len(packet_list)):
            received_packets = self.send_packet_and_capture(packet=packet_list[i])
            received = any(
                packet.haslayer(Raw) and load in str(packet.load) for packet in received_packets
            )
            self.verify(
                received == should_receive,
                f"Packet was {'dropped' if should_receive else 'received'}",
            )

    def send_packet_and_verify_checksum(
        self, packet: Packet, goodL4: bool, goodIP: bool, testpmd: TestPmdShell
    ) -> None:
        """Send packet and verify verbose output matches expected output.

        Args:
            packet: Scapy packet to send to DUT.
            goodL4: Verifies RTE_MBUF_F_RX_L4_CKSUM_GOOD in verbose output
                if :data:`True`, or RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN if :data:`False`.
            goodIP: Verifies RTE_MBUF_F_RX_IP_CKSUM_GOOD in verbose output
                if :data:`True`, or RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN if :data:`False`.
            testpmd: Testpmd shell session to analyze verbose output of.
        """
        testpmd.start()
        self.send_packet_and_capture(packet=packet)
        verbose_output = testpmd.extract_verbose_output(testpmd.stop())
        for packet in verbose_output:
            if packet.dst_mac == "00:00:00:00:00:01":
                if OLFlag.RTE_MBUF_F_RX_L4_CKSUM_GOOD in packet.ol_flags:
                    isIP = True
                else:
                    isIP = False
                if OLFlag.RTE_MBUF_F_RX_L4_CKSUM_GOOD in packet.ol_flags:
                    isL4 = True
                else:
                    isL4 = False
            else:
                isIP = False
                isL4 = False
        self.verify(isL4 == goodL4, "Layer 4 checksum flag did not match expected checksum flag.")
        self.verify(isIP == goodIP, "IP checksum flag did not match expected checksum flag.")

    def setup_hw_offload(self, testpmd: TestPmdShell) -> None:
        """Sets IP, UDP, TCP, and SCTP layers to hardware offload."""
        testpmd.port_stop(port=0)
        testpmd.csum_set_hw(layer=ChecksumOffloadOptions.ip, port_id=0)
        testpmd.csum_set_hw(layer=ChecksumOffloadOptions.udp, port_id=0)
        testpmd.csum_set_hw(layer=ChecksumOffloadOptions.tcp, port_id=0)
        testpmd.csum_set_hw(layer=ChecksumOffloadOptions.sctp, port_id=0)
        testpmd.port_start(port=0)

    def test_insert_checksums(self) -> None:
        """Enable checksum offload insertion and verify packet reception."""
        payload = "xxxxx"
        mac_id = "00:00:00:00:00:01"
        packet_list = [
            Ether(dst=mac_id) / IP() / UDP() / Raw(payload),
            Ether(dst=mac_id) / IP() / TCP() / Raw(payload),
            Ether(dst=mac_id) / IP() / SCTP() / Raw(payload),
            Ether(dst=mac_id) / IPv6(src="::1") / UDP() / Raw(payload),
            Ether(dst=mac_id) / IPv6(src="::1") / TCP() / Raw(payload),
        ]
        with TestPmdShell(node=self.sut_node, enable_rx_cksum=True) as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.csum)
            testpmd.set_verbose(level=1)
            self.setup_hw_offload(testpmd=testpmd)
            testpmd.start()
            self.send_packet_and_verify(packet_list=packet_list, load=payload, should_receive=True)
            for i in range(0, len(packet_list)):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=True, goodIP=True, testpmd=testpmd
                )

    def test_no_insert_checksums(self) -> None:
        """Enable checksum offload insertion and verify packet reception."""
        payload = "xxxxx"
        mac_id = "00:00:00:00:00:01"
        packet_list = [
            Ether(dst=mac_id) / IP() / UDP() / Raw(payload),
            Ether(dst=mac_id) / IP() / TCP() / Raw(payload),
            Ether(dst=mac_id) / IP() / SCTP() / Raw(payload),
            Ether(dst=mac_id) / IPv6(src="::1") / UDP() / Raw(payload),
            Ether(dst=mac_id) / IPv6(src="::1") / TCP() / Raw(payload),
        ]
        with TestPmdShell(node=self.sut_node, enable_rx_cksum=True) as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.csum)
            testpmd.set_verbose(level=1)
            testpmd.start()
            self.send_packet_and_verify(packet_list=packet_list, load=payload, should_receive=True)
            for i in range(0, len(packet_list)):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=True, goodIP=True, testpmd=testpmd
                )

    def test_validate_rx_checksum(self) -> None:
        """Verify verbose output of Rx packets matches expected behavior."""
        mac_id = "00:00:00:00:00:01"
        packet_list = [
            Ether(dst=mac_id) / IP() / UDP(),
            Ether(dst=mac_id) / IP() / TCP(),
            Ether(dst=mac_id) / IP() / SCTP(),
            Ether(dst=mac_id) / IPv6(src="::1") / UDP(),
            Ether(dst=mac_id) / IPv6(src="::1") / TCP(),
            Ether(dst=mac_id) / IP(chksum=0x0) / UDP(chksum=0xF),
            Ether(dst=mac_id) / IP(chksum=0x0) / TCP(chksum=0xF),
            Ether(dst=mac_id) / IP(chksum=0x0) / SCTP(chksum=0xf),
            Ether(dst=mac_id) / IPv6(src="::1") / UDP(chksum=0xF),
            Ether(dst=mac_id) / IPv6(src="::1") / TCP(chksum=0xF),
        ]
        with TestPmdShell(node=self.sut_node, enable_rx_cksum=True) as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.csum)
            testpmd.set_verbose(level=1)
            self.setup_hw_offload(testpmd=testpmd)
            for i in range(0, 5):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=True, goodIP=True, testpmd=testpmd
                )
            for i in range(5, 8):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=False, goodIP=False, testpmd=testpmd
                )
            for i in range(8, 10):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=False, goodIP=True, testpmd=testpmd
                )

    def test_l4_rx_checksum(self) -> None:
        """Tests L4 Rx checksum in a variety of scenarios."""
        mac_id = "00:00:00:00:00:01"
        packet_list = [
            Ether(dst=mac_id) / IP() / UDP(),
            Ether(dst=mac_id) / IP() / TCP(),
            Ether(dst=mac_id) / IP() / SCTP(),
            Ether(dst=mac_id) / IP() / UDP(chksum=0xF),
            Ether(dst=mac_id) / IP() / TCP(chksum=0xF),
            Ether(dst=mac_id) / IP() / SCTP(chksum=0xf)
        ]
        with TestPmdShell(node=self.sut_node, enable_rx_cksum=True) as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.csum)
            testpmd.set_verbose(level=1)
            self.setup_hw_offload(testpmd=testpmd)
            for i in range(0, 3):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=True, goodIP=True, testpmd=testpmd
                )
            for i in range(3, 6):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=False, goodIP=True, testpmd=testpmd
                )

    def test_l3_rx_checksum(self) -> None:
        """Tests L3 Rx checksum hardware offload."""
        mac_id = "00:00:00:00:00:01"
        packet_list = [
            Ether(dst=mac_id) / IP() / UDP(),
            Ether(dst=mac_id) / IP() / TCP(),
            Ether(dst=mac_id) / IP() / SCTP(),
            Ether(dst=mac_id) / IP(chksum=0xF) / UDP(),
            Ether(dst=mac_id) / IP(chksum=0xF) / TCP(),
            Ether(dst=mac_id) / IP(chksum=0xf) / SCTP()
        ]
        with TestPmdShell(node=self.sut_node, enable_rx_cksum=True) as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.csum)
            testpmd.set_verbose(level=1)
            self.setup_hw_offload(testpmd=testpmd)
            for i in range(0, 3):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=True, goodIP=True, testpmd=testpmd
                )
            for i in range(3, 6):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=True, goodIP=False, testpmd=testpmd
                )

    def test_vlan_checksum(self) -> None:
        """Tests VLAN Rx checksum hardware offload and verify packet reception."""
        payload = "xxxxx"
        mac_id = "00:00:00:00:00:01"
        packet_list = [
            Ether(dst=mac_id) / Dot1Q(vlan=1) / IP(chksum=0x0) / UDP(chksum=0xF) / Raw(payload),
            Ether(dst=mac_id) / Dot1Q(vlan=1) / IP(chksum=0x0) / TCP(chksum=0xF) / Raw(payload),
            Ether(dst=mac_id) / Dot1Q(vlan=1) / IP(chksum=0x0) / SCTP(chksum=0x0) / Raw(payload),
            Ether(dst=mac_id) / Dot1Q(vlan=1) / IPv6(src="::1") / UDP(chksum=0xF) / Raw(payload),
            Ether(dst=mac_id) / Dot1Q(vlan=1) / IPv6(src="::1") / TCP(chksum=0xF) / Raw(payload),
        ]
        with TestPmdShell(node=self.sut_node, enable_rx_cksum=True) as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.csum)
            testpmd.set_verbose(level=1)
            self.setup_hw_offload(testpmd=testpmd)
            testpmd.start()
            self.send_packet_and_verify(packet_list=packet_list, load=payload, should_receive=True)
            for i in range(0, 3):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=False, goodIP=False, testpmd=testpmd
                )
            for i in range(3, 5):
                self.send_packet_and_verify_checksum(
                    packet=packet_list[i], goodL4=False, goodIP=True, testpmd=testpmd
                )
