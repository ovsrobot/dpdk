"""Basic L2 forwarding test suite.

This testing suites runs basic L2 forwarding on testpmd with different queue sizes per port.
The forwarding test is performed with several packets being sent at once.
"""

from framework.params.testpmd import EthPeer, SimpleForwardingModes
from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite
from framework.testbed_model.cpu import LogicalCoreCount
from framework.utils import generate_random_packets


class TestL2fwd(TestSuite):
    """L2 forwarding test suite."""

    #: The total number of packets to generate and send for forwarding.
    NUMBER_OF_PACKETS_TO_SEND = 50
    #: The payload size to use for the generated packets in bytes.
    PAYLOAD_SIZE = 100

    def set_up_suite(self) -> None:
        """Set up the test suite.

        Setup:
            Verify that we have at least 2 ports in the current test. Generate the random packets
            that will be sent and spawn a reusable testpmd shell.
        """
        self.verify(len(self.sut_node.ports) >= 2, "At least 2 ports are required for this test.")
        self.packets = generate_random_packets(self.NUMBER_OF_PACKETS_TO_SEND, self.PAYLOAD_SIZE)

    def test_l2fwd_integrity(self) -> None:
        """Test the L2 forwarding integrity.

        Test:
            Configure a testpmd shell with a different numbers of queues per run. Start up L2
            forwarding, send random packets from the TG and verify they were all received back.
        """
        queues = [1, 2, 4, 8]

        with TestPmdShell(
            self.sut_node,
            lcore_filter_specifier=LogicalCoreCount(cores_per_socket=4),
            forward_mode=SimpleForwardingModes.mac,
            eth_peer=[EthPeer(1, self.tg_node.ports[1].mac_address)],
            disable_device_start=True,
        ) as shell:
            for queues_num in queues:
                self._logger.info(f"Testing L2 forwarding with {queues_num} queue(s)")
                shell.set_ports_queues(queues_num)
                shell.start()

                received_packets = self.send_packets_and_capture(self.packets)

                expected_packets = [self.get_expected_packet(packet) for packet in self.packets]
                self.match_all_packets(expected_packets, received_packets)

                shell.stop()
