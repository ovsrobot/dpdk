# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 University of New Hampshire

"""DPDK IP GRE test suite."""

from scapy.layers.inet import GRE, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.sctp import SCTP
from scapy.packet import Packet

from api.capabilities import (
    NicCapability,
    requires_nic_capability,
)
from api.packet import send_packet_and_capture
from api.test import verify
from api.testpmd import TestPmd
from api.testpmd.config import SimpleForwardingModes
from api.testpmd.types import (
    ChecksumOffloadOptions,
    PacketOffloadFlag,
    RtePTypes,
    TestPmdVerbosePacket,
)
from framework.test_suite import TestSuite, func_test

SRC_ID = "FF:FF:FF:FF:FF:FF"


class TestIpGre(TestSuite):
    """IP GRE test suite."""

    def _check_for_matching_packet(
        self, output: list[TestPmdVerbosePacket], flags: RtePTypes
    ) -> bool:
        """Returns :data:`True` if the packet in verbose output contains all specified flags."""
        for packet in output:
            if packet.src_mac == SRC_ID:
                if flags not in packet.hw_ptype and flags not in packet.sw_ptype:
                    return False
        return True

    def _send_packet_and_verify_flags(
        self, expected_flag: RtePTypes, packet: Packet, testpmd: TestPmd
    ) -> None:
        """Sends a packet to the DUT and verifies the verbose ptype flags."""
        send_packet_and_capture(packet=packet)
        verbose_output = testpmd.extract_verbose_output(testpmd.stop(verify=True))
        valid = self._check_for_matching_packet(output=verbose_output, flags=expected_flag)
        verify(valid, f"Packet type flag did not match the expected flag: {expected_flag}.")

    def _setup_session(
        self, testpmd: TestPmd, expected_flags: list[RtePTypes], packet_list=list[Packet]
    ) -> None:
        """Sets the forwarding and verbose mode of each test case interactive shell session."""
        testpmd.set_forward_mode(SimpleForwardingModes.rxonly)
        testpmd.set_verbose(level=1)
        for i in range(0, len(packet_list)):
            testpmd.start(verify=True)
            self._send_packet_and_verify_flags(
                expected_flag=expected_flags[i], packet=packet_list[i], testpmd=testpmd
            )

    def _send_packet_and_verify_checksum(
        self, packet: Packet, good_L4: bool, good_IP: bool, testpmd: TestPmd
    ) -> None:
        """Send packet and verify verbose output matches expected output."""
        testpmd.start()
        send_packet_and_capture(packet=packet)
        verbose_output = testpmd.extract_verbose_output(testpmd.stop())
        is_IP = is_L4 = None
        for testpmd_packet in verbose_output:
            if testpmd_packet.src_mac == SRC_ID:
                is_IP = PacketOffloadFlag.RTE_MBUF_F_RX_IP_CKSUM_GOOD in testpmd_packet.ol_flags
                is_L4 = PacketOffloadFlag.RTE_MBUF_F_RX_L4_CKSUM_GOOD in testpmd_packet.ol_flags
        verify(
            is_IP is not None and is_L4 is not None,
            "Test packet was dropped when it should have been received.",
        )
        verify(is_L4 == good_L4, "Layer 4 checksum flag did not match expected checksum flag.")
        verify(is_IP == good_IP, "IP checksum flag did not match expected checksum flag.")

    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_GRE_TNL_TSO)
    @func_test
    def gre_ip4_pkt_detect(self) -> None:
        """GRE IP4 packet send and detect.

        Steps:
            * Craft packets using GRE tunneling.
            * Send them to the testpmd application.

        Verify:
            * All packets were received.
        """
        packets = [
            Ether(src=SRC_ID) / IP() / GRE() / IP() / UDP(),
            Ether(src=SRC_ID) / IP() / GRE() / IP() / TCP(),
            Ether(src=SRC_ID) / IP() / GRE() / IP() / SCTP(),
            Ether(src=SRC_ID) / Dot1Q() / IP() / GRE() / IP() / UDP(),
            Ether(src=SRC_ID) / Dot1Q() / IP() / GRE() / IP() / TCP(),
            Ether(src=SRC_ID) / Dot1Q() / IP() / GRE() / IP() / SCTP(),
        ]
        flags = [
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV4
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_UDP,
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV4
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_TCP,
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV4
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_SCTP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV4
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_UDP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV4
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_TCP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV4
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_SCTP,
        ]
        with TestPmd() as testpmd:
            self._setup_session(testpmd=testpmd, expected_flags=flags, packet_list=packets)

    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_GRE_TNL_TSO)
    @func_test
    def gre_ip6_outer_ip4_inner_pkt_detect(self) -> None:
        """GRE IPv6 outer and IPv4 inner send and detect.

        Steps:
            * Craft packets using GRE tunneling.
            * Send them to the testpmd application.

        Verify:
            * All packets were received.
        """
        packets = [
            Ether(src=SRC_ID) / IPv6() / GRE() / IP() / UDP(),
            Ether(src=SRC_ID) / IPv6() / GRE() / IP() / TCP(),
            Ether(src=SRC_ID) / IPv6() / GRE() / IP() / SCTP(),
            Ether(src=SRC_ID) / Dot1Q() / IPv6() / GRE() / IP() / UDP(),
            Ether(src=SRC_ID) / Dot1Q() / IPv6() / GRE() / IP() / TCP(),
            Ether(src=SRC_ID) / Dot1Q() / IPv6() / GRE() / IP() / SCTP(),
        ]
        flags = [
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_UDP,
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_TCP,
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_SCTP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_UDP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_TCP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV4
            | RtePTypes.INNER_L4_SCTP,
        ]
        with TestPmd() as testpmd:
            self._setup_session(testpmd=testpmd, expected_flags=flags, packet_list=packets)

    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_GRE_TNL_TSO)
    @func_test
    def gre_ip6_outer_ip6_inner_pkt_detect(self) -> None:
        """GRE IPv6 outer and inner send and detect.

        Steps:
            * Craft packets using GRE tunneling.
            * Send them to the testpmd application.

        Verify:
            * All packets were received.
        """
        packets = [
            Ether(src=SRC_ID) / IPv6() / GRE() / IPv6() / UDP(),
            Ether(src=SRC_ID) / IPv6() / GRE() / IPv6() / TCP(),
            Ether(src=SRC_ID) / IPv6() / GRE() / IPv6() / SCTP(),
            Ether(src=SRC_ID) / Dot1Q() / IPv6() / GRE() / IPv6() / UDP(),
            Ether(src=SRC_ID) / Dot1Q() / IPv6() / GRE() / IPv6() / TCP(),
            Ether(src=SRC_ID) / Dot1Q() / IPv6() / GRE() / IPv6() / SCTP(),
        ]
        flags = [
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV6
            | RtePTypes.INNER_L4_UDP,
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV6
            | RtePTypes.INNER_L4_TCP,
            RtePTypes.L2_ETHER
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV6
            | RtePTypes.INNER_L4_SCTP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV6
            | RtePTypes.INNER_L4_UDP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV6
            | RtePTypes.INNER_L4_TCP,
            RtePTypes.L2_ETHER_VLAN
            | RtePTypes.L3_IPV6
            | RtePTypes.TUNNEL_GRE
            | RtePTypes.INNER_L3_IPV6
            | RtePTypes.INNER_L4_SCTP,
        ]
        with TestPmd() as testpmd:
            self._setup_session(testpmd=testpmd, expected_flags=flags, packet_list=packets)

    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_OUTER_IPV4_CKSUM)
    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_IPV4_CKSUM)
    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_TCP_CKSUM)
    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_UDP_CKSUM)
    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_SCTP_CKSUM)
    @requires_nic_capability(NicCapability.PORT_TX_OFFLOAD_GRE_TNL_TSO)
    @func_test
    def gre_checksum_offload(self) -> None:
        """GRE checksum offload test.

        Steps:
            * Craft packets using GRE tunneling.
            * Alter checksum of each packet.
            * Send packets to the testpmd application.

        Verify:
            * All packets were received with the expected checksum flags.
        """
        packets = [
            Ether(src=SRC_ID) / IP(chksum=0x0) / GRE() / IP() / TCP(),
            Ether(src=SRC_ID) / IP() / GRE() / IP(chksum=0x0) / TCP(),
            Ether(src=SRC_ID) / IP() / GRE() / IP() / TCP(chksum=0x0),
            Ether(src=SRC_ID) / IP() / GRE() / IP() / UDP(chksum=0xFFFF),
            Ether(src=SRC_ID) / IP() / GRE() / IP() / SCTP(chksum=0x0),
        ]
        good_l4_ip = [
            (True, True),
            (True, False),
            (False, True),
            (False, True),
            (False, True),
        ]
        with TestPmd() as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.csum)
            testpmd.csum_set_hw(
                layers=ChecksumOffloadOptions.ip
                | ChecksumOffloadOptions.udp
                | ChecksumOffloadOptions.outer_ip
                | ChecksumOffloadOptions.sctp
                | ChecksumOffloadOptions.tcp,
                port_id=0,
            )
            testpmd.set_csum_parse_tunnel(port=0, on=True)
            testpmd.set_verbose(1)
            testpmd.start_all_ports()
            testpmd.start()
            for i in range(len(packets)):
                self._send_packet_and_verify_checksum(
                    packets[i],
                    good_l4_ip[i][0],
                    good_l4_ip[i][1],
                    testpmd,
                )
