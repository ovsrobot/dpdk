# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 Arm Limited

"""PMD RSS Test Suite Utils.

Utility functions for the pmd_rss_... test suite series
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
from framework.test_suite import TestSuite


def VerifyHashQueue(
    test_suite: TestSuite,
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

        # Verify packets are in the correct queue
        test_suite.verify(
            predicted_queue == packet_queue,
            "Packet sent by the Traffic Generator has no RSS queue attribute.",
        )

        if verify_packet_pairs:
            hash_list.append(packet_hash)

    if verify_packet_pairs:
        # Go through pairs of hashes in list and verify they are the same
        for odd_hash, even_hash in zip(hash_list[0::2], hash_list[1::2]):
            test_suite.verify(
                odd_hash == even_hash,
                "Packet pair do not have same hash. Hash algorithm is not symmetric.",
            )


def SendTestPackets(
    TestSuite: TestSuite,
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
        send_additional_mirrored_packet: Send an additional mirrored packet for each packet sent.

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
    TestSuite.send_packets_and_capture(packets)

    # Stop packet capture and revert verbose packet information
    testpmd_shell_out = testpmd.stop()
    testpmd.set_verbose(0)
    # Parse the packets and return them
    return testpmd.extract_verbose_output(testpmd_shell_out)


def SetupRssEnvironment(
    TestSuite: TestSuite,
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
    ports = []
    for port_id, _ in enumerate(TestSuite.topology.sut_ports):
        ports.append(port_id)

    port_info = testpmd.show_port_info(ports[0])

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
        testpmd.flow_create(flow_rule, ports[0])

    # Configure the RETA with random queues
    reta: list[int] = []
    for i in range(reta_size):
        reta.insert(i, random.randint(0, num_queues - 1))
        testpmd.port_config_rss_reta(ports[0], i, reta[i])

    return reta, key_size
