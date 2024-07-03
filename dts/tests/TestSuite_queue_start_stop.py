# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 University of New Hampshire

"""Rx/Tx queue start and stop functionality suite.

This suite tests the ability of the poll mode driver to start and
stop either the Rx or Tx queue (depending on the port) during runtime,
and verify that packets are not received when one is disabled.

Given a paired port topology, the Rx queue will be disabled on port 0,
and the Tx queue will be disabled on port 1.

"""

from scapy.layers.inet import IP  # type: ignore[import-untyped]
from scapy.layers.l2 import Ether  # type: ignore[import-untyped]
from scapy.packet import Raw  # type: ignore[import-untyped]

from framework.remote_session.testpmd_shell import SimpleForwardingModes, TestPmdShell
from framework.test_suite import TestSuite


class TestQueueStartStop(TestSuite):
    """DPDK Queue start/stop test suite.

    Ensures Rx/Tx queue on a port can be disabled and enabled.
    Verifies packets are not received when either queue is disabled.
    The suite contains two test cases, Rx queue start/stop and
    Tx queue start/stop, which each disable the corresponding
    queue and verify that packets are not received/forwarded.
    """

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Verify that at least two ports are open for session.
        """
        self.verify(len(self._port_links) > 1, "Not enough ports")

    def send_packet_and_verify(self, should_receive: bool = True):
        """Generate a packet, send to the DUT, and verify it is forwarded back.

        Args:
            should_receive: Indicate whether the packet should be received.
        """
        packet = Ether() / IP() / Raw(load="xxxxx")
        received = self.send_packet_and_capture(packet)
        contains_packet = any(
            packet.haslayer(Raw) and b"xxxxx" in packet.load for packet in received
        )
        self.verify(
            should_receive == contains_packet,
            f"Packet was {'dropped' if should_receive else 'received'}",
        )

    def test_rx_queue_start_stop(self) -> None:
        """Verify packets are not received by port 0 when Rx queue is disabled.

        Test:
            Create an interactive testpmd session, stop Rx queue on port 0, verify
            packets are not received.
        """
        testpmd = TestPmdShell(node=self.sut_node)
        testpmd.set_forward_mode(SimpleForwardingModes.mac)
        testpmd.stop_port_queue(0, 0, True)

        testpmd.start()
        self.send_packet_and_verify(should_receive=False)
        stats = testpmd.show_port_stats(port_id=0)
        self.verify(
            stats.rx_packets == 0,
            "Packets were received on Rx queue when it should've been disabled",
        )
        testpmd.close()

    def test_tx_queue_start_stop(self) -> None:
        """Verify packets are not forwarded by port 1 when Tx queue is disabled.

        Test:
            Create an interactive testpmd session, stop Tx queue on port 1, verify
            packets are not forwarded.
        """
        testpmd = TestPmdShell(node=self.sut_node)
        testpmd.set_forward_mode(SimpleForwardingModes.mac)
        testpmd.stop_port_queue(1, 0, False)
        testpmd.start()
        self.send_packet_and_verify(should_receive=False)
        stats = testpmd.show_port_stats(port_id=1)
        self.verify(
            stats.tx_packets == 0,
            "Packets were forwarded on Tx queue when it should've been disabled",
        )
        testpmd.close()
