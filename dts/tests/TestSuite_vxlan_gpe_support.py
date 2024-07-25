# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 University of New Hampshire

"""VXLAN-GPE support test suite.

This suite verifies virtual extensible local area network packets
are only received in the same state when a UDP tunnel port for VXLAN tunneling
protocols is enabled. GPE is the Generic Protocol Extension for VXLAN,
which is used for configuring fields in the VXLAN header through GPE tunnels.

If a GPE tunnel is configured for the corresponding UDP port within a sent packet,
that packet should be received with its VXLAN layer. If there is no GPE tunnel,
the packet should be received without its VXLAN layer.

"""

from scapy.layers.inet import IP, UDP  # type: ignore[import-untyped]
from scapy.layers.l2 import Ether  # type: ignore[import-untyped]
from scapy.layers.vxlan import VXLAN  # type: ignore[import-untyped]
from scapy.packet import Raw  # type: ignore[import-untyped]

from framework.params.testpmd import SimpleForwardingModes
from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite


class TestVxlanGpeSupport(TestSuite):
    """DPDK VXLAN-GPE test suite.

    This suite consists of one test case (Port 4790 is designated for VXLAN-GPE streams):
    1. VXLAN-GPE ipv4 packet detect - configures a GPE tunnel on port 4790
        and sends packets with a matching UDP destination port. This packet
        should be received by the traffic generator with its VXLAN layer.
        Then, remove the GPE tunnel, send the same packet, and verify that
        the packet is received without its VXLAN layer.
    """

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Verify that we have at least 2 port links in the current test run.
        """
        self.verify(
            len(self._port_links) > 1,
            "There must be at least two port links to run the scatter test suite",
        )

    def send_vxlan_packet_and_verify(self, udp_dport: int, should_receive_vxlan: bool) -> None:
        """Generate a VXLAN GPE packet with the given UDP destination port, send and verify.

        Args:
            udp_dport: The destination UDP port to generate in the packet.
            should_receive_vxlan: Indicates whether the packet should be
                received by the traffic generator with its VXLAN layer.
        """
        packet = Ether() / IP() / UDP(dport=udp_dport) / VXLAN(flags=12) / IP() / Raw(load="xxxxx")
        received = self.send_packet_and_capture(packet)
        print(f"Received packets = {received}")
        has_vxlan = any(
            "VXLAN" in packet.summary() and "xxxxx" in str(packet.load) for packet in received
        )
        self.verify(
            not (has_vxlan ^ should_receive_vxlan), "Expected packet did not match received packet."
        )

    def test_gpe_tunneling(self) -> None:
        """Verifies expected behavior of VXLAN packets through a GPE tunnel."""
        GPE_port = 4790
        with TestPmdShell(node=self.sut_node) as testpmd:
            testpmd.set_forward_mode(SimpleForwardingModes.io)
            testpmd.set_verbose(level=1)
            testpmd.start()
            testpmd.udp_tunnel_port(port_id=0, add=True, udp_port=GPE_port, protocol="vxlan")
            self.send_vxlan_packet_and_verify(udp_dport=GPE_port, should_receive_vxlan=True)
            testpmd.udp_tunnel_port(port_id=0, add=False, udp_port=GPE_port, protocol="vxlan")
            self.send_vxlan_packet_and_verify(udp_dport=GPE_port, should_receive_vxlan=False)
