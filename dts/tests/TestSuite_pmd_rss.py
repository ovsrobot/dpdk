# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 Arm Limited

"""RSS testing suite.

This TestSuite tests the following.

RSS Hash Test Cases:
    Hashing algorithms are used in conjunction with a RSS hash keys to hash packets.
    This test suite verifies that updating the Hashing algorithms will
    continue to correctly hash packets.

    Symmetric_toeplitz_sort hasn't been included due to it not being supported by
    the rss func actions in the flow rule.

RSS Key Update Test Cases:
    RSS hash keys are used in conjunction with a hashing algorithm to hash packets.
    This test suite verifies that updating the RSS hash key will change the hash
    generated if the hashing algorithm stays the same.

RSS RETA (redirection table) Test Cases:
    The RETA is used in RSS to redirect packets to different queues based on the
    least significant bits of the packets hash.
    This suite tests updating the size of the RETA and verifying the reported RETA size.
"""

import random

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from framework.exception import InteractiveCommandExecutionError
from framework.params.testpmd import SimpleForwardingModes
from framework.remote_session.testpmd_shell import (
    FlowRule,
    RSSOffloadTypesFlag,
    TestPmdShell,
    TestPmdVerbosePacket,
)
from framework.test_suite import BaseConfig, TestSuite, func_test
from framework.testbed_model.capability import requires
from framework.testbed_model.topology import TopologyType
from framework.utils import StrEnum


class Config(BaseConfig):
    """Default configuration for Per Test Suite config."""

    NUM_QUEUES: int = 4

    ACTUAL_KEY_SIZE: int = 52

    ACTUAL_RETA_SIZE: int = 512


class HashAlgorithm(StrEnum):
    """Enum of hashing algorithms."""

    DEFAULT = "default"
    SIMPLE_XOR = "simple_xor"
    TOEPLITZ = "toeplitz"
    SYMMETRIC_TOEPLITZ = "symmetric_toeplitz"


@requires(topology_type=TopologyType.one_link)
class TestPmdRss(TestSuite):
    """PMD RSS test suite.

    Hash:
        Verifies the redirection table when updating the size.
        The suite contains four tests, one for each hash algorithms.
        Configure the redirection table to have random entries.

    Update:
        Create a flow rule so ipv4-udp packets utilize the desired RSS hash algorithm.
        Send packets, and verify they are in the desired queue based on the redirection table.
        Update the RSS hash key.
        Send packets, and verify they are in the desired queue based on the redirection table.
        Verify the packet hashes before and after the key update are different.

    RSS:
        Verifies the redirection table when updating the size.
        The suite contains four tests, three for different RETA sizes
        and one for verifying the reported RETA size.
    """

    config: Config

    def set_up_suite(self):
        """Generates the queues for the flow rule."""
        self.queue = (
            str([x for x in range(self.config.NUM_QUEUES)])
            .replace(",", "")
            .replace("[", "")
            .replace("]", "")
        )

    def verify_hash_queue(
        self,
        reta: list[int],
        received_packets: list[TestPmdVerbosePacket],
        verify_packet_pairs: bool,
    ) -> None:
        """Verifies the packet hash corresponds to the packet queue.

        Given the received packets in the verbose output, iterate through each packet.
        Lookup the packet hash in the RETA and get its intended queue.
        Verify the intended queue is the same as the actual queue the packet was received in.
        If the hash algorithm is symmetric, verify that pairs of packets have the same hash,
        as the pairs of packets sent have "mirrored" L4 ports.
        e.g. received_packets[0, 1, 2, 3, ...] hash(0) = hash(1), hash(2) = hash(3), ...

        Args:
            test_suite: The reference to the currently running test suite.
            reta: Used to get predicted queue based on hash.
            received_packets: Packets received in the verbose output of testpmd.
            verify_packet_pairs: Verify pairs of packets have the same hash.

        Raises:
            InteractiveCommandExecutionError: If packet_hash is None.
        """
        # List of packet hashes, used for symmetric algorithms
        hash_list = []
        for packet in received_packets:
            if packet.port_id != 0 or packet.src_mac != "02:00:00:00:00:00":
                continue

            # Get packet hash
            packet_hash = packet.rss_hash
            if packet_hash is None:
                raise InteractiveCommandExecutionError(
                    "Packet sent by the Traffic Generator has no RSS hash attribute."
                )

            packet_queue = packet.rss_queue

            # Calculate the predicted packet queue
            predicted_reta_index = packet_hash % len(reta)
            predicted_queue = reta[predicted_reta_index]
            print(
                "\nreta:\n",
                len(reta),
                "\npacket_hash:\n",
                packet_hash,
                "\npredicted queue:\n",
                predicted_queue,
                "\npacket queue:\n",
                packet_queue,
                "\n",
            )
            # Verify packets are in the correct queue
            self.verify(
                predicted_queue == packet_queue,
                "Packet sent by the Traffic Generator has no RSS queue attribute.",
            )

            if verify_packet_pairs:
                hash_list.append(packet_hash)

        if verify_packet_pairs:
            # Go through pairs of hashes in list and verify they are the same
            for odd_hash, even_hash in zip(hash_list[0::2], hash_list[1::2]):
                self.verify(
                    odd_hash == even_hash,
                    "Packet pair do not have same hash. Hash algorithm is not symmetric.",
                )

    def send_test_packets(
        self,
        testpmd: TestPmdShell,
        send_additional_mirrored_packet: bool,
    ) -> list[TestPmdVerbosePacket]:
        """Sends test packets.

        Send 10 packets from the TG to SUT, parsing the verbose output and returning it.
        If the algorithm chosen is symmetric, send an additional packet for each initial
        packet sent, which has the L4 src and dst swapped.

        Args:
            TestSuite: The reference to the currently running test suite.
            testpmd: Used to send packets and send commands to testpmd.
            send_additional_mirrored_packet: Send an additional mirrored packet for each packet
            sent.

        Returns:
            TestPmdVerbosePacket: List of packets.
        """
        # Create test packets
        packets = []
        for i in range(10):
            packets.append(
                Ether(src="02:00:00:00:00:00", dst="11:00:00:00:00:00")
                / IP()
                / UDP(sport=i, dport=i + 1),
            )
            if send_additional_mirrored_packet:  # If symmetric, send the inverse packets
                packets.append(
                    Ether(src="02:00:00:00:00:00", dst="11:00:00:00:00:00")
                    / IP()
                    / UDP(sport=i + 1, dport=i),
                )

        # Set verbose packet information and start packet capture
        testpmd.set_verbose(3)
        testpmd.start()
        testpmd.start_all_ports()
        self.send_packets_and_capture(packets)

        # Stop packet capture and revert verbose packet information
        testpmd_shell_out = testpmd.stop()
        testpmd.set_verbose(0)
        # Parse the packets and return them
        return testpmd.extract_verbose_output(testpmd_shell_out)

    def setup_rss_environment(
        self,
        testpmd: TestPmdShell,
        num_queues: int,
        flow_rule: FlowRule | None,
    ) -> tuple[list[int], int]:
        """Sets up the testpmd environment for RSS test suites.

        This involves:
        1. Setting the testpmd forward mode to rx_only.
        2. Setting RSS on the NIC to UDP.
        3. Creating a flow if provided.
        4. Configuring RETA.

        The reta and key_size of the NIC are then returned

        Args:
            TestSuite: TestSuite environment.
            testpmd: Where the environment will be set.
            num_queues: Number of queues in the RETA table.
            flow_rule: The flow rule for altering packet fate.

        Raises:
            InteractiveCommandExecutionError: If size of hash key for driver is None.
            InteractiveCommandExecutionError: If size of RETA table for driver is None.

        Returns:
            reta: Configured Redirection Table.
            key_size: key size supported by NIC.
        """
        port_info = testpmd.show_port_info(0)

        # Get hash key size
        key_size = port_info.hash_key_size
        if key_size is None:
            raise InteractiveCommandExecutionError("Size of hash key for driver is None.")

        # Get RETA table size
        reta_size = port_info.redirection_table_size
        if reta_size is None:
            raise InteractiveCommandExecutionError("Size of RETA table for driver is None.")

        # Set forward mode to receive only, to remove forwarded packets from verbose output
        testpmd.set_forward_mode(SimpleForwardingModes.rxonly)

        # Reset RSS settings and only RSS udp packets
        testpmd.port_config_all_rss_offload_type(RSSOffloadTypesFlag.udp)

        # Create flow rule
        if flow_rule is not None:
            testpmd.flow_create(flow_rule, 0)

        # Configure the RETA with random queues
        reta: list[int] = []
        for i in range(reta_size):
            reta.insert(i, random.randint(0, num_queues - 1))
            testpmd.port_config_rss_reta(0, i, reta[i])

        return reta, key_size

    def verify_rss_hash_function(
        self, testpmd: TestPmdShell, hash_algorithm: HashAlgorithm, flow_rule: FlowRule
    ) -> None:
        """Verifies the hash function is supported by the NIC.

        Args:
            testpmd: The testpmd instance that will be used to set the rss environment.
            hash_algorithm: The hash algorithm to be tested.
            flow_rule: The flow rule that is to be validated and then created.
        """
        self.verify_else_skip(testpmd.flow_validate(flow_rule, 0), "flow rule failed validation.")
        is_symmetric = hash_algorithm == HashAlgorithm.SYMMETRIC_TOEPLITZ
        # Run the key update test suite with an asymmetric hash algorithm
        # Setup testpmd environment for RSS, create RETA table, return RETA table and key_size
        reta, _ = self.setup_rss_environment(testpmd, self.config.NUM_QUEUES, flow_rule)
        # Send udp packets and ensure hash corresponds with queue
        parsed_output = self.send_test_packets(testpmd, is_symmetric)
        self.verify_hash_queue(reta, parsed_output, is_symmetric)

    def check_reta_n_queues(self, num_queues: int) -> None:
        """Create RETA of size n, send packets, verify packets end up in correct queue.

        Args:
            num_queues: Number of rx/tx queues.
        """
        with TestPmdShell(
            rx_queues=num_queues,
            tx_queues=num_queues,
        ) as testpmd:
            # Setup testpmd for RSS, create RETA table, return RETA table and key_size
            reta, _ = self.setup_rss_environment(testpmd, num_queues, None)

            # Send UDP packets and ensure hash corresponds with queue
            parsed_output = self.send_test_packets(testpmd, False)
            self.verify_hash_queue(reta, parsed_output, False)

    @func_test
    def test_key_hash_default_hash_algorithm(self) -> None:
        """Default hashing algorithm test.

        Steps:
            Setup RSS environment using the default RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[f"rss types ipv4-udp end queues func {str(HashAlgorithm.DEFAULT).lower()}"],
        )
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
        ) as testpmd:
            self.verify_rss_hash_function(testpmd, HashAlgorithm.DEFAULT, flow_rule)

    # Note: Below Testcase packet RSS queue and predict RSS queue are always incorrect on ConnectX
    # nics with the actual packet queue being a random queue that the packet can use that is one of
    # the queues within the flow rule (self.queue).
    @func_test
    def test_key_hash_default_hash_algorithm_queues(self) -> None:
        """Default hashing algorithm test for ConnectX nics.

        Steps:
            Setup RSS environment using the default RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[
                f"rss types ipv4-udp end queues {self.queue} end func "
                + str(HashAlgorithm.DEFAULT).lower()
            ],
        )
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
        ) as testpmd:
            self.verify_rss_hash_function(testpmd, HashAlgorithm.DEFAULT, flow_rule)

    @func_test
    def test_key_hash_toeplitz_hash_algorithm(self) -> None:
        """Toeplitz hashing algorithm test.

        Steps:
            Setup RSS environment using the toeplitz RSS hashing algorithm and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[
                f"rss types ipv4-udp end queues end func {str(HashAlgorithm.TOEPLITZ).lower()}"
            ],
        )
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
        ) as testpmd:
            self.verify_rss_hash_function(testpmd, HashAlgorithm.TOEPLITZ, flow_rule)

    # Note: Below Testcase packet RSS queue and predict RSS queue are always incorrect on ConnectX
    # nics with the actual packet queue being a random queue that the packet can use that is one of
    # the queues within the flow rule (self.queue).
    @func_test
    def test_key_hash_toeplitz_hash_algorithm_queues(self) -> None:
        """Toeplitz hashing algorithm test for ConnectX nics.

        Steps:
            Setup RSS environment using the toeplitz RSS hashing algorithm and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[
                f"rss types ipv4-udp end queues {self.queue} end func "
                + str(HashAlgorithm.TOEPLITZ).lower()
            ],
        )
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
        ) as testpmd:
            self.verify_rss_hash_function(testpmd, HashAlgorithm.TOEPLITZ, flow_rule)

    @func_test
    def test_key_hash_symmetric_toeplitz_hash_algorithm(self) -> None:
        """Symmetric toeplitz hashing algorithm test.

        Steps:
            Setup RSS environment using the symmetric_toeplitz RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[
                "rss types ipv4-udp end queues end func "
                + str(HashAlgorithm.SYMMETRIC_TOEPLITZ).lower()
            ],
        )
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
        ) as testpmd:
            self.verify_rss_hash_function(testpmd, HashAlgorithm.SYMMETRIC_TOEPLITZ, flow_rule)

    # Note: Below Testcase packet RSS queue and predict RSS queue are always incorrect on ConnectX
    # nics with the actual packet queue being a random queue that the packet can use that is one of
    # the queues within the flow rule (self.queue).
    @func_test
    def test_key_hash_symmetric_toeplitz_hash_algorithm_queues(self) -> None:
        """Symmetric toeplitz hashing algorithm test for ConnectX nics.

        Steps:
            Setup RSS environment using the symmetric_toeplitz RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[
                f"rss types ipv4-udp end queues {self.queue} end func "
                + str(HashAlgorithm.SYMMETRIC_TOEPLITZ).lower()
            ],
        )
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
        ) as testpmd:
            self.verify_rss_hash_function(testpmd, HashAlgorithm.SYMMETRIC_TOEPLITZ, flow_rule)

    @func_test
    def test_key_hash_simple_xor_hash_algorithm(self) -> None:
        """Simple xor hashing algorithm test.

        Steps:
            Setup RSS environment using the simple xor RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[
                "rss types ipv4-udp end queues end func " + str(HashAlgorithm.SIMPLE_XOR).lower()
            ],
        )
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
        ) as testpmd:
            self.verify_rss_hash_function(testpmd, HashAlgorithm.SIMPLE_XOR, flow_rule)

    # Note: Below Testcase packet RSS queue and predict RSS queue are always incorrect on ConnectX
    # nics with the actual packet queue being a random queue that the packet can use that is one of
    # the queues within the flow rule (self.queue).
    @func_test
    def test_key_hash_simple_xor_hash_algorithm_queues(self) -> None:
        """Simple xor hashing algorithm test for ConnectX nics.

        Steps:
            Setup RSS environment using the simple xor RSS hashing algorithm
            and send test packets.
        Verify:
            Packet hash corresponds to the packet queue.
        """
        flow_rule = FlowRule(
            group_id=0,
            direction="ingress",
            pattern=["eth / ipv4 / udp"],
            actions=[
                f"rss types ipv4-udp end queues {self.queue} end func "
                + str(HashAlgorithm.SIMPLE_XOR).lower()
            ],
        )
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
        ) as testpmd:
            self.verify_rss_hash_function(testpmd, HashAlgorithm.SIMPLE_XOR, flow_rule)

    @func_test
    def test_update_key_set_hash_key_short_long(self) -> None:
        """Set hash key short long test.

        Steps:
            Fetch the hash key size, create two random hash keys one key that is too short and one
            that is too long.

        Verify:
            Verify that it is not possible to set the shorter hash key.
            Verify that it is not possible to set the longer hash key.

        Raises:
            InteractiveCommandExecutionError: If port info dose not contain hash key size.
        """
        with TestPmdShell(
            memory_channels=4,
            rx_queues=self.config.NUM_QUEUES,
            tx_queues=self.config.NUM_QUEUES,
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
    def test_update_key_reported_key_size(self) -> None:
        """Verify reported hash key size is the same as the NIC capabilities.

        Steps:
            Fetch the hash key size and compare to the actual key size.
        Verify:
            Reported key size is the same as the actual key size.
        """
        with TestPmdShell() as testpmd:
            reported_key_size = testpmd.show_port_info(0).hash_key_size
            self.verify(
                reported_key_size == self.config.ACTUAL_KEY_SIZE,
                "Reported key size is not the same as the config file.",
            )

    @func_test
    def test_reta_key_reta_queues(self) -> None:
        """RETA rx/tx queues test.

        Steps:
            Setup RSS environment and send Test packets.
        Verify:
            Packet hash corresponds to hash queue.
        """
        queues = [2, 9, 16]
        for queue in queues:
            self.check_reta_n_queues(queue)

    @func_test
    def test_reta_key_reported_reta_size(self) -> None:
        """Reported RETA size test.

        Steps:
            Fetch reported reta size.
        Verify:
            Reported RETA size is equal to the actual RETA size.
        """
        with TestPmdShell(
            rx_queues=self.config.NUM_QUEUES, tx_queues=self.config.NUM_QUEUES
        ) as testpmd:
            reported_reta_size = testpmd.show_port_info(0).redirection_table_size
            self.verify(
                reported_reta_size == self.config.ACTUAL_RETA_SIZE,
                "Reported RETA size is not the same as the config file.",
            )
