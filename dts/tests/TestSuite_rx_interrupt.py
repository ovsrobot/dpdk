# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 Isaac Boukris

"""Rx interrupt test suite.

Test that packets received on a port wake up a testpmd lcore that sleeps on the Rx queues'
interrupts. Test it again after the ports are configured again, with the same number of queues
and with another number.
"""

import re

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from api.exception import InteractiveCommandExecutionError
from api.packet import send_packets
from api.test import fail, verify_else_skip
from api.test_suite import TestSuite, func_suite, func_test
from api.testpmd import TestPmd
from api.testpmd.config import SimpleForwardingModes


@func_suite
class TestRxInterrupt(TestSuite):
    """Rx interrupt test suite."""

    #: The number of packets to send. Each of them must wake the lcore up.
    NUMBER_OF_WAKE_UPS = 8

    def _wake_ups(self, testpmd: TestPmd) -> int:
        match = re.search(r"RX-wakeups:\s+(\d+)", testpmd.send_command("show fwd stats all"))
        return int(match.group(1)) if match else 0

    def _verify_wake_ups(self, testpmd: TestPmd) -> str:
        """Verify that packets wake up the lcore of `testpmd`, `NUMBER_OF_WAKE_UPS` times.

        The packets differ in their source address, to spread over the Rx queues.

        A packet is sent only after the previous one woke the lcore up. The lcore is awake for
        a short time every 10 ms, to look at its queues. A packet that arrives then is received
        without a wake-up, so send each packet up to three times.

        Returns:
            The forward statistics that testpmd shows when it stops.
        """
        testpmd.start()
        for number in range(1, self.NUMBER_OF_WAKE_UPS + 1):
            packet = Ether() / IP(src=f"192.168.0.{number}") / UDP() / Raw(b"\0" * 32)
            wake_ups = self._wake_ups(testpmd)
            for _ in range(3):
                send_packets([packet])
                if self._wake_ups(testpmd) > wake_ups:
                    break
            else:
                fail(f"Packet {number} did not wake up the lcore.")
        return testpmd.stop()

    def _configure_again(self, testpmd: TestPmd, number_of_queues: int) -> None:
        """Stop the ports of `testpmd`, configure them with `number_of_queues` and start them."""
        testpmd.set_ports_queues(number_of_queues)
        try:
            testpmd.start_all_ports()
        except InteractiveCommandExecutionError:
            fail(f"The ports did not start, configured with {number_of_queues} queue(s).")

    @func_test
    def wake_up_on_packet(self) -> None:
        """Wake up a sleeping lcore with packets, also after a second configuration.

        Steps:
            * Start testpmd with Rx queue interrupts, receiving.
            * Send packets to the ingress port, one at a time.
            * Stop the ports, configure them again with the same number of queues, start them
              and send again.

        Verify:
            * Each packet wakes up the lcore from the queue's interrupt.
            * The ports start after the second configuration.
        """
        with TestPmd(rxq_interrupt=True, forward_mode=SimpleForwardingModes.rxonly) as testpmd:
            self._verify_wake_ups(testpmd)
            self._configure_again(testpmd, 1)
            self._verify_wake_ups(testpmd)

    @func_test
    def wake_up_on_packet_after_queue_number_change(self) -> None:
        """Wake up a sleeping lcore with packets after the number of queues changed.

        The test case is skipped if a port cannot have two queues, or if the packets do not
        reach both queues.

        Steps:
            * Start testpmd with Rx queue interrupts, receiving, with one queue.
            * Stop the ports, configure them with two queues, start them and send packets to
              the ingress port, one at a time.
            * Do the same with one queue.

        Verify:
            * Each packet wakes up the lcore from a queue's interrupt.
            * With two queues, both queues receive packets.
            * The ports start after each configuration.
        """
        with TestPmd(rxq_interrupt=True, forward_mode=SimpleForwardingModes.rxonly) as testpmd:
            max_queues = min(
                min(port.max_rx_queues_num, port.max_tx_queues_num)
                for port in testpmd.show_port_info_all()
            )
            verify_else_skip(
                max_queues >= 2, f"The test needs 2 queues, and a port has {max_queues} at most."
            )
            self._configure_again(testpmd, 2)
            statistics = self._verify_wake_ups(testpmd)
            # Each packet woke the lcore up. So a queue that received packets woke it up.
            for queue in (0, 1):
                verify_else_skip(
                    f"RX Port= 0/Queue= {queue}" in statistics,
                    f"No packet reached Rx queue {queue} of the ingress port.",
                )
            self._configure_again(testpmd, 1)
            self._verify_wake_ups(testpmd)
