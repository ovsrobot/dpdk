# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire

"""Multi-segment packet scattering testing suite.

Configure the Rx queues to have mbuf data buffers whose sizes are smaller than the maximum packet
size (currently set to 2048 to fit a full 1512-byte ethernet frame) and send a total of 5 packets
with lengths less than, equal to, and greater than the mbuf size (CRC included).
"""
import struct

from scapy.layers.inet import IP  # type: ignore[import]
from scapy.layers.l2 import Ether  # type: ignore[import]
from scapy.packet import Raw  # type: ignore[import]
from scapy.utils import hexstr  # type: ignore[import]

from framework.remote_session.remote.testpmd_shell import (
    TestPmdForwardingModes,
    TestPmdShell,
)
from framework.test_suite import TestSuite


class PmdBufferScatter(TestSuite):
    """DPDK packet scattering test suite.

    Attributes:
        mbsize: The size to se the mbuf to be.
    """

    mbsize: int

    def set_up_suite(self) -> None:
        self.verify(
            len(self._port_links) > 1,
            "Must have at least two port links to run scatter",
        )

        self.tg_node.main_session.configure_port_mtu(9000, self._tg_port_egress)
        self.tg_node.main_session.configure_port_mtu(9000, self._tg_port_ingress)

    def scatter_pktgen_send_packet(self, pktsize: int) -> str:
        """Generate and send packet to the SUT.

        Functional test for scatter packets.

        Args:
            pktsize: Size of the packet to generate and send.
        """
        packet = Ether() / IP() / Raw()
        packet.getlayer(2).load = ""
        payload_len = pktsize - len(packet) - 4
        payload = ["58"] * payload_len
        # pack the payload
        for X_in_hex in payload:
            packet.load += struct.pack("=B", int("%s%s" % (X_in_hex[0], X_in_hex[1]), 16))
        load = hexstr(packet.getlayer(2), onlyhex=1)
        received_packets = self.send_packet_and_capture(packet)
        self.verify(len(received_packets) > 0, "Did not receive any packets.")
        load = hexstr(received_packets[0].getlayer(2), onlyhex=1)

        return load

    def pmd_scatter(self) -> None:
        """Testpmd support of receiving and sending scattered multi-segment packets.

        Support for scattered packets is shown by sending 5 packets of differing length
        where the length of the packet is calculated by taking mbuf-size + an offset. The
        offsets used in the test case are -1, 0, 1, 4, 5 respectively.

        Test:
            Start testpmd and run functional test with preset mbsize.
        """
        testpmd = self.sut_node.create_interactive_shell(
            TestPmdShell,
            app_parameters=(
                "--mbcache=200 "
                f"--mbuf-size={self.mbsize} "
                "--max-pkt-len=9000 "
                "--port-topology=paired "
                "--tx-offloads=0x00008000"
            ),
            privileged=True,
        )
        testpmd.set_forward_mode(TestPmdForwardingModes.mac)
        testpmd.start()
        link_is_up = testpmd.wait_link_status_up(0) and testpmd.wait_link_status_up(1)
        self.verify(link_is_up, "Links never came up in TestPMD.")

        for offset in [-1, 0, 1, 4, 5]:
            recv_payload = self.scatter_pktgen_send_packet(self.mbsize + offset)
            self.verify(
                ("58 " * 8).strip() in recv_payload,
                "Received packet had incorrect payload",
            )
        testpmd.stop()

    def test_scatter_mbuf_2048(self) -> None:
        """Run :func:`~PmdBufferScatter.pmd_scatter` function after setting the `mbsize` to 2048."""
        self.mbsize = 2048
        self.pmd_scatter()

    def tear_down_suite(self) -> None:
        self.tg_node.main_session.configure_port_mtu(1500, self._tg_port_egress)
        self.tg_node.main_session.configure_port_mtu(1500, self._tg_port_ingress)
