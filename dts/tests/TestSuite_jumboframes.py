# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023-2024 University of New Hampshire
"""Jumbo frame consistency and compatibility test suite.

The test suite ensures the consistency of jumbo frames transmission within
Poll Mode Drivers using a series of individual test cases. If a Poll Mode
Driver receives a packet that is greater than its assigned MTU length, then
that packet will be dropped, and thus not received. Likewise, if a Poll Mode Driver
receives a packet that is less than or equal to a its designated MTU length, then the
packet should be transmitted by the Poll Mode Driver, completing a cycle within the
testbed and getting received by the traffic generator. Thus, the following test suite
evaluates the behavior within all possible edge cases, ensuring that a test Poll
Mode Driver strictly abides by the above implications.
"""

from scapy.layers.inet import IP  # type: ignore[import-untyped]
from scapy.layers.l2 import Ether  # type: ignore[import-untyped]
from scapy.packet import Raw  # type: ignore[import-untyped]

from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite

IP_HEADER_LEN = 20
ETHER_STANDARD_FRAME = 1500
ETHER_JUMBO_FRAME_MTU = 9000


class TestJumboframes(TestSuite):
    """DPDK PMD jumbo frames test suite.

    Asserts the expected behavior of frames greater than, less then, or equal to
    a designated MTU size in the testpmd application. If a packet size greater
    than the designated testpmd MTU length is retrieved, the test fails. If a
    packet size less than or equal to the designated testpmd MTU length is retrieved,
    the test passes.
    """

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Set traffic generator MTU lengths to a size greater than scope of all
            test cases.
        """
        self.tg_node.main_session.configure_port_mtu(
            ETHER_JUMBO_FRAME_MTU + 200, self._tg_port_egress
        )
        self.tg_node.main_session.configure_port_mtu(
            ETHER_JUMBO_FRAME_MTU + 200, self._tg_port_ingress
        )

    def send_packet_and_verify(self, pktsize: int, should_receive: bool = True) -> None:
        """Generate, send, and capture packets to verify that the sent packet was received or not.

        Generates a packet based on a specified size and sends it to the SUT. The desired packet's
        payload size is calculated, and arbitrary, byte-sized characters are inserted into the
        packet before sending. Packets are captured, and depending on the test case, packet
        payloads are checked to determine if the sent payload was received.

        Args:
            pktsize: Size of packet to be generated and sent.
            should_receive: Indicate whether the test case expects to receive the packet or not.
        """
        padding = pktsize - IP_HEADER_LEN
        # Insert extra space for placeholder 'CRC' Error correction.
        packet = Ether() / Raw("    ") / IP(len=pktsize) / Raw(load="X" * padding)
        received_packets = self.send_packet_and_capture(packet)
        found = any(
            ("X" * padding) in str(packets.load)
            for packets in received_packets
            if hasattr(packets, "load")
        )

        if should_receive:
            self.verify(found, "Did not receive packet")
        else:
            self.verify(not found, "Received packet")

    def test_jumboframes_normal_nojumbo(self) -> None:
        """Assess the boundaries of packets sent less than or equal to the standard MTU length.

        PMDs are set to the standard MTU length of 1518 to assess behavior of sent packets less than
        or equal to this size. Sends two packets: one that is less than 1518 bytes, and another that
        is equal to 1518 bytes. The test case expects to receive both packets.

        Test:
            Start testpmd and send packets of sizes 1517 and 1518.
        """
        with TestPmdShell(
            self.sut_node, tx_offloads=0x8000, mbuf_size=[9200], mbcache=200
        ) as testpmd:
            testpmd.configure_port_mtu_all(ETHER_STANDARD_FRAME)
            testpmd.start()

            self.send_packet_and_verify(ETHER_STANDARD_FRAME - 5)
            self.send_packet_and_verify(ETHER_STANDARD_FRAME)

    def test_jumboframes_jumbo_nojumbo(self) -> None:
        """Assess the boundaries of packets sent greater than standard MTU length.

        PMDs are set to the standard MTU length of 1518 bytes to assess behavior of sent packets
        greater than this size. Sends one packet with a frame size of 1519. The test cases does
        not expect to receive this packet.

        Test:
            Start testpmd with standard MTU size of 1518. Send a packet of 1519 and verify it was
            not received.
        """
        with TestPmdShell(
            self.sut_node, tx_offloads=0x8000, mbuf_size=[9200], mbcache=200
        ) as testpmd:
            testpmd.configure_port_mtu_all(ETHER_STANDARD_FRAME)
            testpmd.start()

            self.send_packet_and_verify(ETHER_STANDARD_FRAME + 5, False)

    def test_jumboframes_normal_jumbo(self) -> None:
        """Assess the consistency of standard 1518 byte packets using a 9000 byte jumbo MTU length.

        PMDs are set to a jumbo frame size of 9000 bytes. Packets of sizes 1517 and 1518 are sent
        to assess the boundaries of packets less than or equal to the standard MTU length of 1518.
        The test case expects to receive both packets.

        Test:
            Start testpmd with a jumbo frame size of 9000 bytes. Send a packet of 1517 and 1518
            and verify they were received.
        """
        with TestPmdShell(
            self.sut_node, tx_offloads=0x8000, mbuf_size=[9200], mbcache=200
        ) as testpmd:
            testpmd.configure_port_mtu_all(ETHER_JUMBO_FRAME_MTU)
            testpmd.start()

            self.send_packet_and_verify(ETHER_STANDARD_FRAME - 5)
            self.send_packet_and_verify(ETHER_STANDARD_FRAME)

    def test_jumboframes_jumbo_jumbo(self) -> None:
        """Assess the boundaries packets sent at an MTU size of 9000 bytes.

        PMDs are set to a jumbo frames size of 9000 bytes. Packets of size 1519, 8999, and 9000
        are sent. The test expects to receive all packets.

        Test:
            Start testpmd with an MTU length of 9000 bytes. Send packets of size 1519, 8999,
            and 9000 and verify that all packets were received.
        """
        with TestPmdShell(
            self.sut_node, tx_offloads=0x8000, mbuf_size=[9200], mbcache=200
        ) as testpmd:
            testpmd.configure_port_mtu_all(ETHER_JUMBO_FRAME_MTU)
            testpmd.start()

            self.send_packet_and_verify(ETHER_STANDARD_FRAME + 5)
            self.send_packet_and_verify(ETHER_JUMBO_FRAME_MTU - 5)
            self.send_packet_and_verify(ETHER_JUMBO_FRAME_MTU)

    def test_jumboframes_bigger_jumbo(self) -> None:
        """Assess the behavior of packets send greater than a specified MTU length of 9000 bytes.

        PMDs are set to a jumbo frames size of 9000 bytes. A packet of size 9001 is sent to the SUT.
        The test case does not expect to receive the packet.

        Test:
            Start testpmd with an MTU length of 9000 bytes. Send a packet of 9001 bytes and verify
            it was not received.
        """
        with TestPmdShell(
            self.sut_node, tx_offloads=0x8000, mbuf_size=[9200], mbcache=200
        ) as testpmd:
            testpmd.configure_port_mtu_all(ETHER_JUMBO_FRAME_MTU)
            testpmd.start()

            self.send_packet_and_verify(ETHER_JUMBO_FRAME_MTU + 5, False)

    def tear_down_suite(self) -> None:
        """Tear down the test suite.

        Teardown:
            Set the MTU size of the traffic generator back to the standard 1518 byte size.
        """
        self.tg_node.main_session.configure_port_mtu(ETHER_STANDARD_FRAME, self._tg_port_egress)
        self.tg_node.main_session.configure_port_mtu(ETHER_STANDARD_FRAME, self._tg_port_ingress)
