# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 Arm Limited

"""RSS Hash testing suite.

Hashing algorithms are used in conjunction with a RSS hash keys to hash packets.
This test suite verifies that updating the Hashing algorithms will
continue to correctly hash packets.

Symmetric_toeplitz_sort hasn't been included due to it not being supported by
the rss func actions in the flow rule.
"""

from framework.remote_session.testpmd_shell import FlowRule, TestPmdShell
from framework.test_suite import TestSuite, func_test
from framework.testbed_model.capability import NicCapability, requires
from framework.testbed_model.topology import TopologyType
from framework.utils import StrEnum

from .pmd_rss_utils import (  # type: ignore[import-untyped]
    SendTestPackets,
    SetupRssEnvironment,
    VerifyHashQueue,
)

NUM_QUEUES = 16


class HashAlgorithm(StrEnum):
    """Enum of hashing algorithms."""

    DEFAULT = "default"
    SIMPLE_XOR = "simple_xor"
    TOEPLITZ = "toeplitz"
    SYMMETRIC_TOEPLITZ = "symmetric_toeplitz"


@requires(topology_type=TopologyType.one_link)
class TestPmdRssHash(TestSuite):
    """PMD RSS Hash test suite.

    Verifies the redirection table when updating the size.
    The suite contains four tests, one for each hash algorithms.
    """

    def VerifyHashFunction(self, hash_algorithm: HashAlgorithm) -> None:
        """Verifies the hash function is supported by the NIC.

        Args:
            hash_algorithm: The hash algorithm to be tested.
        """
        is_symmetric = hash_algorithm == HashAlgorithm.SYMMETRIC_TOEPLITZ
        # Build flow rule
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[f"rss types ipv4-udp end queues end func {str(hash_algorithm).lower()}"],
        )

        # Run the key update test suite with an asymmetric hash algorithm
        with TestPmdShell(
            rx_queues=NUM_QUEUES,
            tx_queues=NUM_QUEUES,
        ) as testpmd:
            # Setup testpmd environment for RSS, create RETA table, return RETA table and key_size
            reta, _ = SetupRssEnvironment(self, testpmd, NUM_QUEUES, flow_rule)
            # Send udp packets and ensure hash corresponds with queue
            parsed_output = SendTestPackets(self, testpmd, is_symmetric)
            VerifyHashQueue(self, reta, parsed_output, is_symmetric)

    @func_test
    def TestDefaultHashAlgorithm(self) -> None:
        """Default hashing algorithm test.

        Steps:
            Setup RSS environment using the default RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        self.VerifyHashFunction(HashAlgorithm.DEFAULT)

    @func_test
    def TestToeplitzHashAlgorithm(self) -> None:
        """Toeplitz hashing algorithm test.

        Steps:
            Setup RSS environment using the toeplitz RSS hashing algorithm and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        self.VerifyHashFunction(HashAlgorithm.TOEPLITZ)

    @func_test
    def TestSymmetricToeplitzHashAlgorithm(self) -> None:
        """Symmetric toeplitz hashing algorithm test.

        Steps:
            Setup RSS environment using the symmetric_toeplitz RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        self.VerifyHashFunction(HashAlgorithm.SYMMETRIC_TOEPLITZ)

    @requires(NicCapability.XOR_SUPPORT)
    @func_test
    def TestSimpleXorHashAlgorithm(self) -> None:
        """Simple xor hashing algorithm test.

        Steps:
            Setup RSS environment using the simple xor RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        self.VerifyHashFunction(HashAlgorithm.SIMPLE_XOR)
