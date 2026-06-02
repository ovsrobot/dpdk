# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 NVIDIA Corporation & Affiliates

"""Rx split test suite.

Test configuring a packet split on Rx,
and discarding some segments (selective Rx) at NIC level.
"""

from typing import Any

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from api.capabilities import (
    NicCapability,
    requires_nic_capability,
)
from api.packet import send_packet_and_capture
from api.test import fail, verify
from api.testpmd import TestPmd
from api.testpmd.config import SimpleForwardingModes
from api.testpmd.types import RxOffloadCapability, TxOffloadCapability
from framework.exception import InteractiveCommandExecutionError
from framework.test_suite import TestSuite, func_test

PAYLOAD = bytes(range(256))
ETHER_HDR_LEN = len(Ether())
IP_HDR_LEN = len(IP())
ETHER_IP_HDR_LEN = ETHER_HDR_LEN + IP_HDR_LEN


@requires_nic_capability(NicCapability.PORT_RX_OFFLOAD_BUFFER_SPLIT)
@requires_nic_capability(NicCapability.SELECTIVE_RX)
class TestRxSplit(TestSuite):
    """Rx split test suite.

    Configure testpmd with various Rx segment offset/length combinations
    and verify that only the requested portions of the packet are received
    and forwarded.
    """

    def _create_testpmd(self, **kwargs: Any) -> TestPmd:
        """Create a TestPmd instance with defaults overridden by kwargs."""
        defaults: dict[str, Any] = {
            "forward_mode": SimpleForwardingModes.mac,
            "rx_offloads": RxOffloadCapability.BUFFER_SPLIT,
            "enable_scatter": True,
        }
        return TestPmd(**{**defaults, **kwargs})

    def _build_packet(self) -> Packet:
        """Build a test packet with an incrementing byte pattern payload."""
        return Ether() / IP() / Raw(load=PAYLOAD)

    def _send_and_verify(
        self,
        testpmd: TestPmd,
        packet: Packet,
        expected_bytes: bytes,
    ) -> None:
        """Clear stats, send a packet, and verify received content and stats.

        Args:
            testpmd: The running testpmd instance.
            packet: The packet to send.
            expected_bytes: Expected raw bytes of the received packet.
        """
        expected_len = len(expected_bytes)
        testpmd.clear_port_stats_all(verify=False)

        received = send_packet_and_capture(packet)
        verify(
            len(received) > 0,
            "Did not receive any packets.",
        )

        recv_bytes = bytes(received[0])
        verify(
            len(recv_bytes) == expected_len,
            f"Expected packet length {expected_len}, got {len(recv_bytes)}.",
        )
        verify(
            recv_bytes == expected_bytes,
            "Received packet content does not match expected bytes.",
        )

        all_stats, _ = testpmd.show_port_stats_all()
        total_rx_packets = sum(s.rx_packets for s in all_stats)
        total_rx_bytes = sum(s.rx_bytes for s in all_stats)
        verify(
            total_rx_packets == 1,
            f"Expected 1 Rx packet, got {total_rx_packets}.",
        )
        verify(
            total_rx_bytes == expected_len,
            f"Expected {expected_len} Rx bytes, got {total_rx_bytes}.",
        )

    @func_test
    def selective_rx_headers(self) -> None:
        """Keep only the Ethernet + IP headers, discard the payload.

        Steps:
            Start testpmd with rxoffs/rxpkts and buffer split enabled.
            Send an Ether/IP/payload packet.

        Verify:
            Received packet has Ether + IP headers only.
            Port stats show expected rx_packets and rx_bytes.
        """
        with self._create_testpmd(
            rx_segments_offsets=[0],
            rx_segments_length=[ETHER_IP_HDR_LEN],
        ) as testpmd:
            testpmd.start()
            packet = self._build_packet()
            expected = bytes(packet)[:ETHER_IP_HDR_LEN]
            self._send_and_verify(testpmd, packet, expected)

    @func_test
    def selective_rx_payload_only(self) -> None:
        """Skip the Ethernet + IP headers, keep only the payload.

        Steps:
            Start testpmd with rxoffs/rxpkts and buffer split enabled.
            Send an Ether/IP/payload packet.

        Verify:
            Received packet is matching the original payload.
            Port stats show expected rx_packets and rx_bytes.
        """
        with self._create_testpmd(
            rx_segments_offsets=[ETHER_IP_HDR_LEN],
            rx_segments_length=[len(PAYLOAD)],
        ) as testpmd:
            testpmd.start()
            self._send_and_verify(testpmd, self._build_packet(), PAYLOAD)

    @func_test
    def selective_rx_two_segments(self) -> None:
        """Keep the IP header and the middle of the payload, skip the rest.

        Steps:
            Start testpmd with rxoffs/rxpkts, buffer split
            and multi-segment Tx enabled.
            Send an Ether/IP/payload packet.

        Verify:
            Received packet is matching the IP header and middle of payload.
            Port stats show expected rx_packets and rx_bytes.
        """
        payload_offset = 100
        payload_length = 100
        with self._create_testpmd(
            tx_offloads=TxOffloadCapability.MULTI_SEGS,
            rx_segments_offsets=[ETHER_HDR_LEN, ETHER_IP_HDR_LEN + payload_offset],
            rx_segments_length=[IP_HDR_LEN, payload_length],
        ) as testpmd:
            testpmd.start()
            packet = self._build_packet()
            raw = bytes(packet)
            payload_start = ETHER_IP_HDR_LEN + payload_offset
            expected = (
                raw[ETHER_HDR_LEN:ETHER_IP_HDR_LEN]
                + raw[payload_start : payload_start + payload_length]
            )
            self._send_and_verify(testpmd, packet, expected)

    @func_test
    def selective_rx_no_offload(self) -> None:
        """Configure selective Rx with buffer split disabled.

        Steps:
            Start testpmd with rxoffs/rxpkts, buffer split
            and device start disabled.
            Attempt to start ports.

        Verify:
            Queue configuration fails.
        """
        with self._create_testpmd(
            rx_offloads=None,
            rx_segments_offsets=[0],
            rx_segments_length=[ETHER_IP_HDR_LEN],
            disable_device_start=True,
        ) as testpmd:
            try:
                testpmd.start_all_ports()
                fail("Expected configuration to fail with buffer split disabled.")
            except InteractiveCommandExecutionError:
                pass

    @func_test
    def selective_rx_offset_out_of_range(self) -> None:
        """Configure selective Rx with an offset beyond max_rx_pktlen.

        Steps:
            Start testpmd with rxoffs too big, buffer split enabled,
            and device start disabled.
            Attempt to start ports.

        Verify:
            Queue configuration fails.
        """
        with self._create_testpmd(
            rx_segments_offsets=[20000],
            rx_segments_length=[100],
            disable_device_start=True,
        ) as testpmd:
            try:
                testpmd.start_all_ports()
                fail("Expected configuration to fail with out-of-range offset.")
            except InteractiveCommandExecutionError:
                pass

    @func_test
    def selective_rx_overlap(self) -> None:
        """Configure selective Rx with overlapping segments.

        Steps:
            Start testpmd with overlapping rxoffs/rxpkts, buffer split enabled,
            and device start disabled.
            Attempt to start ports.

        Verify:
            Queue configuration fails.
        """
        with self._create_testpmd(
            rx_segments_offsets=[0, 10],
            rx_segments_length=[64, 64],
            disable_device_start=True,
        ) as testpmd:
            try:
                testpmd.start_all_ports()
                fail("Expected configuration to fail with overlapping segments.")
            except InteractiveCommandExecutionError:
                pass

    @func_test
    def selective_rx_all_discard(self) -> None:
        """Configure selective Rx with only discard segment.

        Steps:
            Start testpmd with rxoffs/rxpkts=0 (null segment), buffer split enabled,
            and device start disabled.
            Attempt to start ports.

        Verify:
            Queue configuration fails.
        """
        with self._create_testpmd(
            rx_segments_offsets=[0],
            rx_segments_length=[0],
            disable_device_start=True,
        ) as testpmd:
            try:
                testpmd.start_all_ports()
                fail("Expected configuration to fail with only discard segment.")
            except InteractiveCommandExecutionError:
                pass
