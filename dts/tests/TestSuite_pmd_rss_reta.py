# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 Arm Limited

"""RSS RETA (redirection table) Test Suite.

The RETA is used in RSS to redirect packets to different queues based on the
least significant bits of the packets hash.
This suite tests updating the size of the RETA and verifying the reported RETA size.
"""

from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite, func_test
from framework.testbed_model.capability import requires
from framework.testbed_model.topology import TopologyType

from .pmd_rss_utils import (  # type: ignore[import-untyped]
    SendTestPackets,
    SetupRssEnvironment,
    VerifyHashQueue,
)

ACTUAL_RETA_SIZE = 512


@requires(topology_type=TopologyType.one_link)
class TestPmdRssReta(TestSuite):
    """PMD RSS Reta test suite.

    Verifies the redirection table when updating the size.
    The suite contains four tests, three for different RETA sizes
    and one for verifying the reported RETA size.
    """

    def CheckRetaNQueues(self, num_queues: int) -> None:
        """Create RETA of size n, send packets, verify packets end up in correct queue.

        Args:
            num_queues: Number of rx/tx queues.
        """
        with TestPmdShell(
            rx_queues=num_queues,
            tx_queues=num_queues,
        ) as testpmd:
            # Setup testpmd for RSS, create RETA table, return RETA table and key_size
            reta, _ = SetupRssEnvironment(self, testpmd, num_queues, None)

            # Send UDP packets and ensure hash corresponds with queue
            parsed_output = SendTestPackets(self, testpmd, False)
            VerifyHashQueue(self, reta, parsed_output, False)

    @func_test
    def TestReta2Queues(self) -> None:
        """RETA rx/tx queues 2 test.

        Steps:
            Setup RSS environment and send Test packets.
        Verify:
            Packet hash corresponds to hash queue.
        """
        self.CheckRetaNQueues(2)

    @func_test
    def TestReta9Queues(self) -> None:
        """RETA rx/tx queues 9 test.

        Steps:
            Setup RSS environment and send Test packets.
        Verify:
            Packet hash corresponds to hash queue.
        """
        self.CheckRetaNQueues(9)

    @func_test
    def TestReta16Queues(self) -> None:
        """RETA rx/tx queues 16 test.

        Steps:
            Setup RSS environment and send Test packets.
        Verify:
            Packet hash corresponds to hash queue.
        """
        self.CheckRetaNQueues(16)

    @func_test
    def TestReportedRetaSize(self) -> None:
        """Reported RETA size test.

        Steps:
            Fetch reported reta size.
        Verify:
            Reported RETA size is equal to the actual RETA size.
        """
        with TestPmdShell() as testpmd:
            self.topology.sut_port_egress.config
            # Get RETA table size
            port_info = testpmd.show_port_info(0)
            reported_reta_size = port_info.redirection_table_size
            self.verify(
                reported_reta_size == ACTUAL_RETA_SIZE,
                "Reported RETA size is not the same as the config file.",
            )
