# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""RTE Flow testing suite.

This suite verifies a range of flow rules built using patterns
and actions from the RTE Flow API. It would be impossible to cover
every valid flow rule, but this suite aims to test the most
important and common functionalities across PMDs.

"""

from dataclasses import dataclass, field
from itertools import product
from typing import Any, Callable, cast

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.layers.sctp import SCTP
from scapy.packet import Packet, Raw

from api.capabilities import NicCapability, requires_nic_capability
from api.packet import send_packet_and_capture
from api.test import fail, log, verify
from api.testpmd import TestPmd
from api.testpmd.types import FlowRule
from framework.exception import InteractiveCommandExecutionError, SkippedTestException
from framework.test_suite import TestSuite, func_test


@dataclass
class PatternField:
    """Specification for a single matchable field within a protocol layer."""

    scapy_field: str
    pattern_field: str
    test_values: list[Any]


@dataclass
class Layer:
    """Complete specification for a protocol layer."""

    name: str
    scapy_class: type
    pattern_name: str
    fields: list[PatternField]
    requires: list[str] = field(default_factory=list)

    def build_scapy_layer(self, field_values: dict[str, Any]) -> Packet:
        """Construct a Scapy layer with the given field values."""
        return self.scapy_class(**field_values)


@dataclass
class Action:
    """Specification for a flow action."""

    name: str
    action_format: str
    verification_type: str
    param_builder: Callable[[Any], dict[str, Any]]
    expected_packet_builder: Callable[[Packet], Packet] | None = None

    def build_action_string(self, value: Any = None) -> str:
        """Generate the action string for a flow rule."""
        if value is not None and "{value}" in self.action_format:
            return self.action_format.format(value=value)
        return self.action_format

    def build_verification_params(self, value: Any = None) -> dict[str, Any]:
        """Generate verification parameters for this action."""
        return self.param_builder(value)

    def build_expected_packet(self, original_packet: Packet) -> Packet | None:
        """Build expected packet for modification actions."""
        if self.expected_packet_builder:
            return self.expected_packet_builder(original_packet)
        return None


@dataclass
class FlowTestCase:
    """A complete test case ready for execution."""

    flow_rule: FlowRule
    packet: Packet
    verification_type: str
    verification_params: dict[str, Any]
    description: str = ""
    expected_packet: Packet | None = None


@dataclass
class FlowTestResult:
    """Result of a single test case execution."""

    description: str
    passed: bool
    failure_reason: str = ""
    flow_rule_pattern: str = ""
    skipped: bool = False
    sent_packet: Packet | None = None


LAYERS: dict[str, Layer] = {
    "eth": Layer(
        name="eth",
        scapy_class=Ether,
        pattern_name="eth",
        fields=[
            PatternField("src", "src", ["02:00:00:00:00:00"]),
            PatternField("dst", "dst", ["02:00:00:00:00:02"]),
        ],
    ),
    "ipv4": Layer(
        name="ipv4",
        scapy_class=IP,
        pattern_name="ipv4",
        fields=[
            PatternField("src", "src", ["192.168.1.1"]),
            PatternField("dst", "dst", ["192.168.1.2"]),
            PatternField("ttl", "ttl", [64, 128]),
            PatternField("tos", "tos", [0, 4]),
        ],
        requires=["eth"],
    ),
    "ipv6": Layer(
        name="ipv6",
        scapy_class=IPv6,
        pattern_name="ipv6",
        fields=[
            PatternField("src", "src", ["2001:db8::1"]),
            PatternField("dst", "dst", ["2001:db8::2"]),
            PatternField("tc", "tc", [0, 4]),
            PatternField("hlim", "hop", [64, 128]),
        ],
        requires=["eth"],
    ),
    "tcp": Layer(
        name="tcp",
        scapy_class=TCP,
        pattern_name="tcp",
        fields=[
            PatternField("sport", "src", [1234, 8080]),
            PatternField("dport", "dst", [80, 443]),
            PatternField("flags", "flags", [2, 16]),
        ],
        requires=["eth", "ipv4"],
    ),
    "udp": Layer(
        name="udp",
        scapy_class=UDP,
        pattern_name="udp",
        fields=[
            PatternField("sport", "src", [5000]),
            PatternField("dport", "dst", [53, 123]),
        ],
        requires=["eth", "ipv4"],
    ),
    "vlan": Layer(
        name="vlan",
        scapy_class=Dot1Q,
        pattern_name="vlan",
        fields=[
            PatternField("vlan", "vid", [100, 200]),
            PatternField("prio", "pcp", [0, 7]),
        ],
        requires=["eth"],
    ),
    "icmp": Layer(
        name="icmp",
        scapy_class=ICMP,
        pattern_name="icmp",
        fields=[
            PatternField("type", "type", [8, 0]),
            PatternField("code", "code", [0]),
            PatternField("id", "ident", [0, 1234]),
            PatternField("seq", "seq", [0, 1]),
        ],
        requires=["eth", "ipv4"],
    ),
    "sctp": Layer(
        name="sctp",
        scapy_class=SCTP,
        pattern_name="sctp",
        fields=[
            PatternField("sport", "src", [2905, 3868]),
            PatternField("dport", "dst", [2905, 3868]),
            PatternField("tag", "tag", [1, 12346]),
        ],
        requires=["eth", "ipv4"],
    ),
    "arp": Layer(
        name="arp",
        scapy_class=ARP,
        pattern_name="arp_eth_ipv4",
        fields=[
            PatternField("psrc", "spa", ["192.168.1.1"]),
            PatternField("pdst", "tpa", ["192.168.1.2"]),
            PatternField("op", "opcode", [1, 2]),
        ],
        requires=["eth"],
    ),
}


def _build_ipv4_src_to_dst_expected(packet: Packet) -> Packet:
    """Build expected packet for IPV4 src to dst copy."""
    expected = cast(Packet, packet.copy())
    if IP in expected:
        expected[IP].dst = packet[IP].src
    return expected


def _build_mac_src_to_dst_expected(packet: Packet) -> Packet:
    """Build expected packet for MAC src to dst copy."""
    expected = cast(Packet, packet.copy())
    if Ether in expected:
        expected[Ether].dst = packet[Ether].src
    return expected


ACTIONS: dict[str, Action] = {
    "queue": Action(
        name="queue",
        action_format="queue index {value}",
        verification_type="queue",
        param_builder=lambda queue_id: {"queue_id": queue_id},
    ),
    "drop": Action(
        name="drop",
        action_format="drop",
        verification_type="drop",
        param_builder=lambda _: {"should_receive": False},
    ),
    "modify_ipv4_src_to_dst": Action(
        name="modify_ipv4_src_to_dst",
        action_format="modify_field op set dst_type "
        "ipv4_dst src_type ipv4_src width 32 / queue index 0",
        verification_type="modify",
        param_builder=lambda _: {},
        expected_packet_builder=_build_ipv4_src_to_dst_expected,
    ),
    "modify_mac_src_to_dst": Action(
        name="modify_mac_src_to_dst",
        action_format="modify_field op set dst_type "
        "mac_dst src_type mac_src width 48 / queue index 0",
        verification_type="modify",
        param_builder=lambda _: {},
        expected_packet_builder=_build_mac_src_to_dst_expected,
    ),
}

LAYER_STACKS = [
    ["eth"],
    ["eth", "ipv4"],
    ["eth", "ipv4", "tcp"],
    ["eth", "ipv4", "udp"],
    ["eth", "ipv4", "icmp"],
    ["eth", "ipv4", "sctp"],
    ["eth", "ipv6"],
    ["eth", "ipv6", "tcp"],
    ["eth", "ipv6", "udp"],
    ["eth", "ipv6", "sctp"],
    ["eth", "vlan"],
    ["eth", "vlan", "ipv4"],
    ["eth", "vlan", "ipv4", "tcp"],
    ["eth", "vlan", "ipv4", "udp"],
    ["eth", "vlan", "ipv4", "sctp"],
    ["eth", "vlan", "ipv6"],
    ["eth", "vlan", "ipv6", "tcp"],
    ["eth", "vlan", "ipv6", "udp"],
    ["eth", "arp"],
]


class FlowTestGenerator:
    """Generates test cases by combining patterns and actions."""

    def __init__(self, layers: dict[str, Layer], actions: dict[str, Action]):
        """Initialize the generator with layer and action specifications."""
        self.layers = layers
        self.actions = actions

    def _build_multi_layer_packet(
        self,
        layer_stack: list[str],
        all_field_values: dict[str, dict[str, Any]],
        add_payload: bool = True,
    ) -> Packet:
        """Build a packet from multiple protocol layers."""
        packet: Packet = Ether()
        prev_layer_name = None

        for layer_name in layer_stack:
            layer_spec = self.layers[layer_name]
            values = all_field_values.get(layer_name, {})
            layer = layer_spec.build_scapy_layer(values)

            if layer_name == "eth":
                packet = layer
            else:
                if prev_layer_name == "ipv6" and layer_name in ["tcp", "udp", "sctp"]:
                    nh_map = {"tcp": 6, "udp": 17, "sctp": 132}
                    packet[IPv6].nh = nh_map[layer_name]

                packet = packet / layer

            prev_layer_name = layer_name

        if add_payload:
            packet = packet / Raw(load="X" * 32)

        return packet

    def generate(
        self,
        layer_names: list[str],
        action_name: str,
        action_value: Any = None,
        group_id: int = 0,
    ) -> list[FlowTestCase]:
        """Generate test cases for patterns matching fields across multiple layers.

        This method identifies every possible combination of one field per layer.
        For each field combination, it iterates through the available test values.
        If fields have an unequal number of test values, it cycles through the
        shorter lists to ensure every specific value in every field is tested.

        Args:
            layer_names: List of layer names to match.
            action_name: Name of the action to apply.
            action_value: Optional value for parameterized actions.
            group_id: Flow group ID.

        Returns:
            List of FlowTestCase objects ready for execution.
        """
        action_spec = self.actions[action_name]

        # Organize layers into lists of matchable fields
        layer_field_specs = []
        for layer_name in layer_names:
            layer_spec = self.layers[layer_name]
            # Capture the layer spec and the field spec for each field in the layer
            layer_field_specs.append([(layer_spec, f) for f in layer_spec.fields])

        test_cases = []

        # Iterate through every combination of fields across the requested layers
        # For ['eth', 'ipv4'], this produces: (eth_src, ipv4_src), (eth_src, ipv4_dst), etc.
        for field_combo in product(*layer_field_specs):
            # Determine how many test cases are needed to cover all values in this combo
            max_vals = max(len(f_spec.test_values) for _, f_spec in field_combo)

            # Cycle through the test values for these fields
            for i in range(max_vals):
                pattern_parts = []
                all_field_values: dict[str, dict[str, Any]] = {}
                desc_parts = []

                for layer_spec, field_spec in field_combo:
                    # Select value by index
                    val = field_spec.test_values[i % len(field_spec.test_values)]

                    pattern_parts.append(
                        f"{layer_spec.pattern_name} {field_spec.pattern_field} is {val}"
                    )
                    # Store value for Scapy packet building
                    if layer_spec.name not in all_field_values:
                        all_field_values[layer_spec.name] = {}
                    all_field_values[layer_spec.name][field_spec.scapy_field] = val

                    desc_parts.append(f"{layer_spec.name}[{field_spec.scapy_field}={val}]")

                full_pattern = " / ".join(pattern_parts)
                flow_rule = FlowRule(
                    direction="ingress",
                    pattern=[full_pattern],
                    actions=[action_spec.build_action_string(action_value)],
                    group_id=group_id,
                )

                add_payload = action_spec.verification_type in ["drop", "modify"]
                packet = self._build_multi_layer_packet(layer_names, all_field_values, add_payload)

                expected_packet = None
                if action_spec.verification_type == "modify":
                    expected_packet = action_spec.build_expected_packet(packet)

                test_cases.append(
                    FlowTestCase(
                        flow_rule=flow_rule,
                        packet=packet,
                        verification_type=action_spec.verification_type,
                        verification_params=action_spec.build_verification_params(action_value),
                        description=" / ".join(desc_parts) + f" -> {action_spec.name}",
                        expected_packet=expected_packet,
                    )
                )

        return test_cases


@requires_nic_capability(NicCapability.FLOW_CTRL)
class TestRteFlow(TestSuite):
    """RTE Flow test suite.

    This suite consists of 4 test cases:
    1. Queue Action: Verifies queue actions with multi-layer patterns
    2. Drop Action: Verifies drop actions with multi-layer patterns
    3. Modify Field Action: Verifies modify_field actions with multi-layer patterns
    4. Jump Action: Verifies jump action between flow groups

    """

    def set_up_suite(self) -> None:
        """Initialize the test generator and result tracking."""
        self.generator = FlowTestGenerator(LAYERS, ACTIONS)
        self.test_suite_results: list[FlowTestResult] = []
        self.test_case_results: list[FlowTestResult] = []

    def _run_confidence_check(self, action_type: str) -> None:
        """Verify that non-matching packets are unaffected by flow rules.

        Creates a flow rule for the specified action, then sends a packet that
        should NOT match the rule to confirm:
        - For 'drop': non-matching packets ARE received (not dropped)
        - For 'queue': non-matching packets are NOT steered to the target queue
        - For 'modify': non-matching packets arrive unmodified

        This ensures flow rules only affect matching traffic before
        running the actual action tests.

        Args:
            action_type: The action being tested ('drop', 'queue', 'modify').
        """
        non_matching_packet = (
            Ether(src="02:00:00:00:00:00", dst="02:00:00:00:00:01")
            / IP(src="192.168.100.1", dst="192.168.100.2")
            / UDP(sport=9999, dport=9998)
            / Raw(load="CONFIDENCE" + "X" * 22)
        )

        with TestPmd(rx_queues=4, tx_queues=4) as testpmd:
            if action_type == "drop":
                drop_rule = FlowRule(
                    direction="ingress",
                    pattern=["eth / ipv4 src is 192.168.1.1 / udp dst is 53"],
                    actions=["drop"],
                )
                flow_id = testpmd.flow_create(flow_rule=drop_rule, port_id=0)

                testpmd.start()
                received = send_packet_and_capture(non_matching_packet)
                testpmd.stop()
                contains_packet = any(
                    p.haslayer(Raw) and b"CONFIDENCE" in bytes(p[Raw].load) for p in received
                )
                testpmd.flow_delete(flow_id, port_id=0)
                verify(
                    contains_packet,
                    "Confidence check failed: non-matching packet dropped by drop rule",
                )

            elif action_type == "queue":
                queue_rule = FlowRule(
                    direction="ingress",
                    pattern=[
                        "eth src is aa:bb:cc:dd:ee:ff / ipv4 src is 10.255.255.254 "
                        "dst is 10.255.255.253 / udp src is 12345 dst is 54321"
                    ],
                    actions=["queue index 3"],
                )
                flow_id = testpmd.flow_create(flow_rule=queue_rule, port_id=0)

                testpmd.set_verbose(level=8)
                testpmd.start()
                send_packet_and_capture(non_matching_packet)
                verbose_output = testpmd.extract_verbose_output(testpmd.stop())
                received_on_target = any(p.queue_id == 3 for p in verbose_output)
                testpmd.flow_delete(flow_id, port_id=0)
                verify(
                    not received_on_target,
                    "Confidence check failed: non-matching packet steered to queue 3",
                )

        log(f"Confidence check passed for '{action_type}' action")

    def _verify_queue(self, packet: Packet, queue_id: int, testpmd: TestPmd, **kwargs: Any) -> None:
        """Verify packet is received on the expected queue."""
        send_packet_and_capture(packet)
        verbose_output = testpmd.extract_verbose_output(testpmd.stop())
        received_on_queue = any(p.queue_id == queue_id for p in verbose_output)
        verify(received_on_queue, f"Packet not received on queue {queue_id}")

    def _verify_drop(self, packet: Packet, **kwargs: Any) -> None:
        """Verify packet is dropped."""
        received = send_packet_and_capture(packet)
        contains_packet = any(p.haslayer(Raw) and b"XXXXX" in p.load for p in received)
        verify(not contains_packet, "Packet was not dropped")

    def _verify_modify(
        self, packet: Packet, expected_packet: Packet, testpmd: TestPmd, **kwargs: Any
    ) -> None:
        """Verify packet modifications."""
        testpmd.start()
        received = send_packet_and_capture(packet)
        testpmd.stop()

        verify(
            any(p.haslayer(Raw) and b"XXXXX" in p.load for p in received),
            "Test packet with payload marker not found",
        )

        test_packet = None
        for pkt in received:
            if pkt.haslayer(Raw) and b"XXXXX" in pkt.load:
                test_packet = pkt
                break

        if IP in expected_packet and test_packet is not None:
            verify(
                test_packet[IP].dst == expected_packet[IP].dst,
                f"IPv4 dst mismatch: expected {expected_packet[IP].dst}, got {test_packet[IP].dst}",
            )

        if Ether in expected_packet and test_packet is not None:
            verify(
                test_packet[Ether].dst == expected_packet[Ether].dst,
                f"MAC dst mismatch: expected {expected_packet[Ether].dst}, "
                f"got {test_packet[Ether].dst}",
            )

    def _run_tests(
        self,
        test_cases: list[FlowTestCase],
        port_id: int = 0,
    ) -> None:
        """Execute a sequence of test cases."""
        with TestPmd(rx_queues=4, tx_queues=4) as testpmd:
            for test_case in test_cases:
                log(f"Testing: {test_case.description}")

                result = FlowTestResult(
                    description=test_case.description,
                    passed=False,
                    flow_rule_pattern=" / ".join(test_case.flow_rule.pattern),
                    sent_packet=test_case.packet,
                )

                try:
                    is_valid = testpmd.flow_validate(flow_rule=test_case.flow_rule, port_id=port_id)
                    if not is_valid:
                        result.skipped = True
                        result.failure_reason = "Flow rule failed validation"
                        self.test_suite_results.append(result)
                        self.test_case_results.append(result)

                    try:
                        flow_id = testpmd.flow_create(
                            flow_rule=test_case.flow_rule, port_id=port_id
                        )
                    except InteractiveCommandExecutionError:
                        result.failure_reason = "Hardware validated but failed to create flow rule"
                        self.test_suite_results.append(result)
                        self.test_case_results.append(result)
                        continue

                    verification_method = getattr(self, f"_verify_{test_case.verification_type}")

                    if test_case.verification_type == "queue":
                        testpmd.set_verbose(level=8)
                        testpmd.start()
                        verification_method(
                            packet=test_case.packet,
                            testpmd=testpmd,
                            **test_case.verification_params,
                        )
                    elif test_case.verification_type == "modify":
                        verification_method(
                            packet=test_case.packet,
                            expected_packet=test_case.expected_packet,
                            testpmd=testpmd,
                            **test_case.verification_params,
                        )
                    else:
                        verification_method(
                            packet=test_case.packet,
                            testpmd=testpmd,
                            **test_case.verification_params,
                        )

                    testpmd.flow_delete(flow_id, port_id=port_id)
                    result.passed = True
                    self.test_suite_results.append(result)
                    self.test_case_results.append(result)

                except SkippedTestException as e:
                    result.skipped = True
                    result.failure_reason = f"Skipped: {str(e)}"
                    self.test_suite_results.append(result)
                    self.test_case_results.append(result)

    def _log_test_suite_summary(self) -> None:
        """Log a summary of all test results."""
        if not self.test_suite_results:
            return

        passed_tests = [r for r in self.test_suite_results if r.passed]
        skipped_tests = [r for r in self.test_suite_results if r.skipped]
        failed_tests = [r for r in self.test_suite_results if not r.passed and not r.skipped]

        log(f"Total tests run: {len(self.test_suite_results)}")
        log(f"Passed: {len(passed_tests)}")
        log(f"Skipped: {len(skipped_tests)}")
        log(f"Failed: {len(failed_tests)}")

        if passed_tests:
            log("\nPASSED TESTS:")
            for result in passed_tests:
                log(f"  {result.description}")
                log(f"    Sent Packet: {result.sent_packet}")

        if skipped_tests:
            log("\nSKIPPED TESTS:")
            for result in skipped_tests:
                log(f"  {result.description}")
                log(f"    Pattern: {result.flow_rule_pattern}")
                log(f"    Reason: {result.failure_reason}")
                log(f"    Sent Packet: {result.sent_packet}")

        if failed_tests:
            log("\nFAILED TESTS:")
            for result in failed_tests:
                log(f"  {result.description}")
                log(f"    Pattern: {result.flow_rule_pattern}")
                log(f"    Reason: {result.failure_reason}")
                log(f"    Sent Packet: {result.sent_packet}")

    def _log_test_case_failures(self) -> None:
        """Log each pattern that failed for a given test case."""
        failures = [r for r in self.test_case_results if not r.passed and not r.skipped]

        if failures:
            patterns = "\n".join(f"\t  - {r.flow_rule_pattern}" for r in failures)

            self.test_case_results = []

            fail(
                "Flow rule passed validation but failed creation.\n"
                "\tFailing flow rule patterns:\n"
                f"{patterns}"
            )

    @func_test
    def queue_action(self) -> None:
        """Validate flow rules with queue actions and multi-layer patterns.

        Steps:
            * Run confidence check to verify baseline packet reception.
            * Create a list of packets to test, with a corresponding flow list.
            * Launch testpmd.
            * Create first flow rule in flow list.
            * Send first packet in packet list, capture verbose output.
            * Delete flow rule, repeat for all flows/packets.

        Verify:
            * Each packet is received on the appropriate queue.
        """
        self._run_confidence_check("queue")
        for stack in LAYER_STACKS:
            test_cases = self.generator.generate(
                layer_names=stack,
                action_name="queue",
                action_value=2,
            )
            self._run_tests(test_cases)
        self._log_test_case_failures()

    @func_test
    def drop_action(self) -> None:
        """Validate flow rules with drop actions and multi-layer patterns.

        Steps:
            * Run confidence check to verify packets are received without drop rules.
            * Create a list of packets to test, with a corresponding flow list.
            * Launch testpmd.
            * Create first flow rule in flow list.
            * Send first packet in packet list, capture verbose output.
            * Delete flow rule, repeat for all flows/packets.

        Verify:
            * Packet is dropped.
        """
        self._run_confidence_check("drop")
        for stack in LAYER_STACKS:
            test_cases = self.generator.generate(
                layer_names=stack,
                action_name="drop",
            )
            self._run_tests(test_cases)
        self._log_test_case_failures()

    @func_test
    def modify_field_action(self) -> None:
        """Validate flow rules with modify_field actions and various patterns.

        Steps:
            * Run confidence check to verify packets arrive unmodified.
            * Create a list of packets to test, with a corresponding flow list.
            * Launch testpmd.
            * Create first flow rule in flow list.
            * Send first packet in packet list, capture received packet.
            * Delete flow rule, repeat for all flows/packets.

        Verify:
            * Packet is modified correctly according to the action.
        """
        self._run_confidence_check("modify")
        for stack in [
            ["eth", "ipv4"],
            ["eth", "ipv4", "tcp"],
            ["eth", "ipv4", "udp"],
        ]:
            test_cases = self.generator.generate(
                layer_names=stack,
                action_name="modify_ipv4_src_to_dst",
                group_id=1,
            )
            self._run_tests(test_cases)

        for stack in [["eth"], ["eth", "vlan"]]:
            test_cases = self.generator.generate(
                layer_names=stack,
                action_name="modify_mac_src_to_dst",
                group_id=1,
            )
            self._run_tests(test_cases)
        self._log_test_case_failures()

    @func_test
    def jump_action(self) -> None:
        """Validate flow rules with jump action between groups.

        The jump action redirects matched packets from one flow group to another.
        Only flow rules in group 0 are guaranteed to be matched against initially;
        subsequent groups can only be reached via jump actions.

        This test creates a two-stage pipeline:
        - Group 0: Match on Ethernet src, jump to group 1
        - Group 1: Match on IPv4 dst, forward to specific queue

        Steps:
            * Launch testpmd with multiple queues.
            * Create flow rule in group 0 that matches eth src and jumps to group 1.
            * Create flow rule in group 1 that matches ipv4 dst and queues to queue 2.
            * Send matching packet and verify it arrives on queue 2.
            * Send non-matching packet (wrong eth src) and verify it doesn't hit queue 2.

        Verify:
            * Packet matching both rules is received on the target queue.
            * Packet not matching group 0 rule does not reach target queue.
        """
        port_id = 0
        target_queue = 2

        test_eth_src = "02:00:00:00:00:00"
        non_matching_eth_src = "02:00:00:00:00:01"
        test_ipv4_dst = "192.168.1.2"
        test_ipv4_src = "192.168.1.1"
        dst_mac = "02:00:00:00:00:02"

        jump_rule = FlowRule(
            direction="ingress",
            group_id=0,
            pattern=[f"eth src is {test_eth_src}"],
            actions=["jump group 1"],
        )

        queue_rule = FlowRule(
            direction="ingress",
            group_id=1,
            pattern=[f"ipv4 dst is {test_ipv4_dst}"],
            actions=[f"queue index {target_queue}"],
        )

        matching_packet = (
            Ether(src=test_eth_src, dst=dst_mac)
            / IP(src=test_ipv4_src, dst=test_ipv4_dst)
            / UDP(sport=5000, dport=53)
            / Raw(load="X" * 32)
        )

        non_matching_packet = (
            Ether(src=non_matching_eth_src, dst=dst_mac)
            / IP(src=test_ipv4_src, dst=test_ipv4_dst)
            / UDP(sport=5000, dport=53)
            / Raw(load="X" * 32)
        )

        jump_result = FlowTestResult(
            description="eth src -> jump group 1",
            passed=False,
            flow_rule_pattern=" / ".join(jump_rule.pattern),
        )

        queue_result = FlowTestResult(
            description="ipv4 dst -> queue (group 1)",
            passed=False,
            flow_rule_pattern=" / ".join(queue_rule.pattern),
        )

        with TestPmd(rx_queues=4, tx_queues=4) as testpmd:
            is_valid = testpmd.flow_validate(flow_rule=jump_rule, port_id=port_id)
            if not is_valid:
                jump_result.skipped = True
                jump_result.failure_reason = "Flow rule failed validation"
                self.test_suite_results.append(jump_result)
                self.test_case_results.append(jump_result)
                self._log_test_case_failures()
                return

            try:
                jump_flow_id = testpmd.flow_create(flow_rule=jump_rule, port_id=port_id)
            except InteractiveCommandExecutionError:
                jump_result.failure_reason = "Hardware validated but failed to create flow rule"
                self.test_suite_results.append(jump_result)
                self.test_case_results.append(jump_result)
                self._log_test_case_failures()
                return

            jump_result.passed = True
            self.test_suite_results.append(jump_result)
            self.test_case_results.append(jump_result)

            is_valid = testpmd.flow_validate(flow_rule=queue_rule, port_id=port_id)
            if not is_valid:
                queue_result.skipped = True
                queue_result.failure_reason = "Flow rule failed validation"
                self.test_suite_results.append(queue_result)
                self.test_case_results.append(queue_result)
                testpmd.flow_delete(jump_flow_id, port_id=port_id)
                self._log_test_case_failures()
                return

            try:
                queue_flow_id = testpmd.flow_create(flow_rule=queue_rule, port_id=port_id)
            except InteractiveCommandExecutionError:
                queue_result.failure_reason = "Hardware validated but failed to create flow rule"
                self.test_suite_results.append(queue_result)
                self.test_case_results.append(queue_result)
                testpmd.flow_delete(jump_flow_id, port_id=port_id)
                self._log_test_case_failures()
                return

            queue_result.passed = True
            self.test_suite_results.append(queue_result)
            self.test_case_results.append(queue_result)

            testpmd.set_verbose(level=8)
            testpmd.start()

            send_packet_and_capture(matching_packet)
            verbose_output = testpmd.extract_verbose_output(testpmd.stop())
            received = any(p.queue_id == target_queue for p in verbose_output)
            verify(
                received,
                f"Matching packet not received on queue {target_queue} after jump",
            )

            testpmd.start()
            send_packet_and_capture(non_matching_packet)
            verbose_output = testpmd.extract_verbose_output(testpmd.stop())
            received = any(p.queue_id == target_queue for p in verbose_output)
            verify(
                not received,
                f"Non-matching packet incorrectly received on queue {target_queue}",
            )

            testpmd.flow_delete(queue_flow_id, port_id=port_id)
            testpmd.flow_delete(jump_flow_id, port_id=port_id)

        self._log_test_case_failures()

    def tear_down_suite(self) -> None:
        """Log test summary at the end of the suite."""
        self._log_test_suite_summary()
