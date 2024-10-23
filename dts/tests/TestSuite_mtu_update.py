# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Arm Limited

"""The DPDK MTU update app test suite.

The MTU is how many bytes an ethernet frame can contain.
This suite tests updating the MTU and verifies that the NIC accepts packets smaller than
the or equal to new MTU and rejects packets larger.
"""

from scapy.layers.inet import IP  # type: ignore[import-untyped]
from scapy.layers.l2 import Ether  # type: ignore[import-untyped]
from scapy.packet import Raw  # type: ignore[import-untyped]

from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite

IP_HEADER_LEN = 20  # IP overhead length
STANDARD_MTU = 1500  # Default MTU size
JUMBO_FRAME_MTU = 9000  # Jumbo MTU size
VLAN_PADDING = 5  # Manufacturer overhead to account for VLAN size


class TestMtuUpdate(TestSuite):
    """DPDK MTU update test suite."""

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Teardown:
            Set the MTU on the TG higher than any test will use, so it will not fragment packets.
        """
        self.tg_node.main_session.configure_port_mtu(JUMBO_FRAME_MTU + 200, self._tg_port_egress)
        self.tg_node.main_session.configure_port_mtu(JUMBO_FRAME_MTU + 200, self._tg_port_ingress)

    def send_packet_and_verify(self, ether_frame_size: int, should_receive: bool) -> None:
        """Generate, send, and capture packets to verify that the sent packet was received or not.

        Calculate the payload size by subtracting the IP header size from frame size.
        Then, craft a packet with the payload being X's and the 4-byte CRC being replaced by "FCRC".
        The packet is then sent.
        If the packet is expected to be received, verify the full payload is within the received
        packets.
        If the packet is not expected to be received, verify the full payload is not within the
        received packets.

        Args:
            ether_frame_size: Ethernet frame size of the packet to be generated and sent.
            should_receive: Whether the test case expects to receive the packet or not.
        """
        # Calculate appropriate payload size.
        payload = ether_frame_size - IP_HEADER_LEN

        # Insert fake CRC('FCRC') at the end of the packet to account for CRC length.
        packet = Ether() / IP(len=ether_frame_size) / Raw(load="X" * payload) / Raw("FCRC")

        # Sends packet and checks if it was received.
        received_packets = self.send_packet_and_capture(packet)

        found = any(
            ("X" * payload) in str(packets.load)
            for packets in received_packets
            if hasattr(packets, "load")
        )

        # Verify if the packet was received when it should have been, and vice versa.
        if should_receive:
            self.verify(
                found,
                f"Did not receive packet smaller than or equal to the MTU: {ether_frame_size}.",
            )
        else:
            self.verify(not found, f"Received a packet larger than the MTU: {ether_frame_size}.")

    def set_and_check_mtu(self, new_mtu: int) -> None:
        """Sets the new MTU and verifies packets smaller than or equal to it will be
            received and packets larger will not.

        First, start testpmd and update the MTU. Then ensure the new value appears
        on port info for all ports.
        Next, start packet capturing and send 3 different lengths of packet and verify
        they are handled correctly.
            # 1. VLAN_PADDING units smaller than the MTU specified.
            # 2. Equal to the MTU specified.
            # 3. VLAN_PADDING units larger than the MTU specified (should be fragmented).
        Finally, stop packet capturing.

        Args:
            new_mtu: New Maximum Transmission Unit to be tested.
        """
        with TestPmdShell(
            self.sut_node,
            tx_offloads=0x8000,
            mbuf_size=[9200],
            max_pkt_len=9200,
            enable_scatter=True,
        ) as testpmd:
            # Configure the new MTU.
            testpmd.set_port_mtu_all(new_mtu)

            # Start packet capturing.
            testpmd.start()

            # Send 3 packets of different sizes (accounting for the size of VLAN).
            # 1. VLAN_PADDING units smaller than the MTU specified.
            # 2. Equal to the MTU specified.
            # 3. VLAN_PADDING units larger than the MTU specified (should be fragmented).
            smaller_frame_size: int = new_mtu - VLAN_PADDING
            equal_frame_size: int = new_mtu
            larger_frame_size: int = new_mtu + VLAN_PADDING
            self.send_packet_and_verify(ether_frame_size=smaller_frame_size, should_receive=True)
            self.send_packet_and_verify(ether_frame_size=equal_frame_size, should_receive=True)
            self.send_packet_and_verify(ether_frame_size=larger_frame_size, should_receive=False)

    def test_mtu_1500(self) -> None:
        """Verify MTU of size 1500.

        Test:
            Set and check MTU of size 1500.
        """
        self.set_and_check_mtu(1500)

    def test_mtu_2400(self) -> None:
        """Verify MTU of size 2400.

        Test:
            Set and check MTU of size 2400.
        """
        self.set_and_check_mtu(2400)

    def test_mtu_4800(self) -> None:
        """Verify MTU of size 4800.

        Test:
            Set and check MTU of size 4800.
        """
        self.set_and_check_mtu(4800)

    def test_mtu_9000(self) -> None:
        """Verify MTU of size 9000.

        Test:
            Set and check MTU of size 9000.
        """
        self.set_and_check_mtu(9000)

    def tear_down_suite(self) -> None:
        """Tear down the test suite.

        Teardown:
            Set the MTU on the TG back to the standard 1500.
        """
        self.tg_node.main_session.configure_port_mtu(STANDARD_MTU, self._tg_port_egress)
        self.tg_node.main_session.configure_port_mtu(STANDARD_MTU, self._tg_port_ingress)
