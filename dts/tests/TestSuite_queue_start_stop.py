# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 University of New Hampshire

"""Rx/Tx queue start and stop functionality suite.

This suite tests the ability of the poll mode driver to start and
stop either the Rx or Tx queue (depending on the port) during runtime,
and verify that packets are not received when one is disabled.

Given a paired port topology, the Rx queue will be disabled on port 0,
and the Tx queue will be disabled on port 1.

"""

from scapy.layers.inet import IP  # type: ignore[import]
from scapy.layers.l2 import Ether  # type: ignore[import]
from scapy.packet import Raw  # type: ignore[import]

from framework.remote_session.testpmd_shell import TestPmdForwardingModes, TestPmdShell
from framework.test_suite import TestSuite

class TestQueueStartStop(TestSuite):
    """DPDK Queue start/stop test suite.

    Ensures Rx/Tx queue on a port can be disabled and enabled.
    Verifies packets are not received when either queue is disabled.
    """

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Create a testpmd session and set up tg nodes
            verify that at least two ports are open for session
        """
        self.verify(len(self._port_links) > 1, "Not enough ports")

    def send_packet_and_verify(self, should_receive: bool = True):
        """Generate a packet, send to the DUT, and verify it is forwarded back.

        Args:
            should_receive: indicate whether the packet should be received
        """
        packet = Ether()/IP()/Raw(load="xxxxx")
        received = self.send_packet_and_capture(packet)
        test_packet = None
        for packet in received:
            if packet.haslayer(Raw) and packet[Raw].load == b'xxxxx':
                test_packet = packet
                break
        if should_receive:
            self.verify(test_packet is not None, "Packet was dropped when it should have been received")
        else:
            self.verify(test_packet is None, "Packet was received when it should have been dropped")

    def test_all_queues_enabled(self) -> None:
        """Ensure packets are received when both Tx and Rx queues are enabled.

        Test:
            Create an interactive testpmd session, stop Rx queue on port 0, verify
            packets are dropped. Then start port 0 Rx queue, stop port 1 Tx queue, and
            verify packets are dropped."""
        testpmd = self.sut_node.create_interactive_shell(TestPmdShell, privileged=True)
        testpmd.set_forward_mode(TestPmdForwardingModes.mac)
        testpmd.stop_port_queue(0, 0, True)

        testpmd.start()
        self.send_packet_and_verify(False)
        testpmd.stop()

        testpmd.start_port_queue(0, 0, True)
        testpmd.stop_port_queue(1, 0, False)

        testpmd.start()
        self.send_packet_and_verify(False)
        testpmd.close()

    def tear_down_suite(self) -> None:
        """Tear down the suite."""
