# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 Arm Limited

"""RSS Key Update testing suite.

RSS hash keys are used in conjunction with a hashing algorithm to hash packets.
This test suite verifies that updating the RSS hash key will change the hash
generated if the hashing algorithm stays the same.
"""

import random

from framework.exception import InteractiveCommandExecutionError
from framework.remote_session.testpmd_shell import (
    FlowRule,
    RSSOffloadTypesFlag,
    TestPmdShell,
)
from framework.test_suite import TestSuite, func_test
from framework.testbed_model.capability import requires
from framework.testbed_model.topology import TopologyType

from .pmd_rss_utils import (  # type: ignore[import-untyped]
    SendTestPackets,
    SetupRssEnvironment,
    VerifyHashQueue,
)

NUM_QUEUES = 16

ACTUAL_KEY_SIZE = 52


@requires(topology_type=TopologyType.one_link)
class TestPmdRssKeyUpdate(TestSuite):
    """The DPDK RSS key update test suite.

    Configure the redirection table to have random entries.
    Create a flow rule so ipv4-udp packets utalise the desired RSS hash algorithm.
    Send packets, and verify they are in the desired queue based on the redirection table.
    Update the RSS hash key.
    Send packets, and verify they are in the desired queue based on the redirection table.
    Verify the packet hashes before and after the key update are different.
    """

    @func_test
    def TestKeyUpdate(
        self,
    ) -> None:
        """Update RSS hash key test.

        Steps:
            Setup the RSS environment, send test packet verify the hash queue based on the
            RETA table, Reset the flow rules and update the hash key.
            Create the flow and send/verify the hash/queue of the packets again.

        Verify:
            Verify the packet hashes before and after the hash key was updated are not the same.
            to show the key update was successful.
        """
        # Create flow rule
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=["rss types ipv4-udp end queues end func default"],
        )

        with TestPmdShell(
            memory_channels=4,
            rx_queues=NUM_QUEUES,
            tx_queues=NUM_QUEUES,
        ) as testpmd:
            # Setup testpmd environment for RSS, create RETA table, return RETA table and key_size
            reta, key_size = SetupRssEnvironment(self, testpmd, NUM_QUEUES, flow_rule)

            # Send UDP packets and ensure hash corresponds with queue
            pre_update_output = SendTestPackets(self, testpmd, False)

            VerifyHashQueue(self, reta, pre_update_output, False)

            # Reset RSS settings and only RSS UDP packets
            testpmd.port_config_all_rss_offload_type(RSSOffloadTypesFlag.udp)

            # Create new hash key and update it
            new_hash_key = "".join([random.choice("0123456789ABCDEF") for n in range(key_size * 2)])
            testpmd.port_config_rss_hash_key(0, RSSOffloadTypesFlag.ipv4_udp, new_hash_key)

            # Create flow rule

            for port_id, _ in enumerate(self.topology.sut_ports):
                testpmd.flow_create(flow_rule, port_id)

            # Send UDP packets and ensure hash corresponds with queue
            post_update_output = SendTestPackets(self, testpmd, False)
            VerifyHashQueue(self, reta, pre_update_output, False)

            self.verify(
                pre_update_output != post_update_output,
                "The hash key had no effect on the packets hash.",
            )

    @func_test
    def TestSetHashKeyShortLong(self) -> None:
        """Set hash key short long test.

        Steps:
            Fetch the hash key size, create two random hash keys one key that is too short and one
            that is too long.

        Verify:
            Verify that it is not possible to set the shorter key.
            Verify that it is not possible to set the longer key.

        Raises:
            InteractiveCommandExecutionError: If port info dose not contain hash key size.
        """
        with TestPmdShell(
            memory_channels=4,
            rx_queues=NUM_QUEUES,
            tx_queues=NUM_QUEUES,
        ) as testpmd:
            # Get RETA and key size
            port_info = testpmd.show_port_info(0)

            # Get hash key size
            key_size = port_info.hash_key_size
            if key_size is None:
                raise InteractiveCommandExecutionError("Port info does not contain hash key size.")

            # Create 2 hash keys based on the NIC capabilities
            short_key = "".join(
                [random.choice("0123456789ABCDEF") for n in range(key_size * 2 - 2)]
            )
            long_key = "".join([random.choice("0123456789ABCDEF") for n in range(key_size * 2 + 2)])

            # Verify a short key cannot be set
            short_key_out = testpmd.port_config_rss_hash_key(
                0, RSSOffloadTypesFlag.ipv4_udp, short_key, False
            )
            self.verify(
                "invalid" in short_key_out,
                "Able to set hash key shorter than specified.",
            )

            # Verify a long key cannot be set
            long_key_out = testpmd.port_config_rss_hash_key(
                0, RSSOffloadTypesFlag.ipv4_udp, long_key, False
            )
            self.verify("invalid" in long_key_out, "Able to set hash key longer than specified.")

    @func_test
    def TestReportedKeySize(self) -> None:
        """Verify reported hash key size is the same as the NIC capabilities.

        Steps:
            Fetch the hash key size and compare to the actual key size.
        Verify:
            Reported key size is the same as the actual key size.
        """
        with TestPmdShell() as testpmd:
            port_info = testpmd.show_port_info(0)
            reported_key_size = port_info.hash_key_size

            self.verify(
                reported_key_size == ACTUAL_KEY_SIZE,
                "Reported key size is not the same as the config file.",
            )
