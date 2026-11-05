# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 University of New Hampshire

"""Eventdev pipeline performance test suite.

This suite measures the packet rate forwarded through the DPDK event device pipeline using the
dpdk-test-eventdev application. For each set of parameters in the test config, which consist of a
scheduled type list, a frame size and the expected MPPS, a performance traffic generator sends
traffic through the pipeline. The measured MPPS is compared against the expected baseline.
"""

import time

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from api.capabilities import (
    LinkTopology,
    requires_link_topology,
)
from api.eventdev import Eventdev
from api.packet import assess_performance_by_packet
from api.test import verify, write_performance_json
from api.test_suite import BaseConfig, TestSuite, perf_test, perf_suite


class Config(BaseConfig):
    """Performance test metrics.

    Attributes:
        test: The eventdev test to run.
        num_workers: The number of worker cores.
        pool_size: The size of the mbuf mempool.
        test_parameters: The scheduled type list, frame size and expected MPPS of each test run.
        delta_tolerance: The allowed tolerance below a given baseline.
        link_up_delay: The time in seconds to wait for the links to come up.
    """

    test: str = "pipeline_queue"
    num_workers: int = 1
    pool_size: int = 16384
    test_parameters: list[dict[str, int | float | str]] = [
        {"stlist": "a", "frame_size": 64, "expected_mpps": 1.00},
        {"stlist": "a", "frame_size": 128, "expected_mpps": 1.00},
        {"stlist": "a", "frame_size": 256, "expected_mpps": 1.00},
        {"stlist": "a", "frame_size": 512, "expected_mpps": 1.00},
        {"stlist": "a", "frame_size": 1024, "expected_mpps": 1.00},
        {"stlist": "a", "frame_size": 1518, "expected_mpps": 1.00},
    ]
    delta_tolerance: float = 0.05
    link_up_delay: int = 5

@perf_suite
@requires_link_topology(LinkTopology.TWO_LINKS)
class TestEventdevPipelinePerf(TestSuite):
    """Eventdev pipeline performance test suite."""

    config: Config

    def _transmit(self, frame_size: int, repetitions: int = 1) -> float:
        """Send packets of the given size and measure the average Rx rate.

        Args:
            frame_size: The size of the frames to send.
            repetitions: The number of times to send traffic.

        Returns:
            The average Rx rate in MPPS.
        """
        assert repetitions > 0, "Invalid number of repetitions given."
        # Build packet with dummy values, and account for the 14B and 20B Ether and IP headers.
        packet = (
            Ether(src="52:00:00:00:00:00")
            / IP(src="1.2.3.4", dst="192.18.1.0")
            / Raw(load="x" * (frame_size - 14 - 20))
        )

        rx_avg = 0.0
        for _ in range(repetitions):
            stats = assess_performance_by_packet(packet=packet, duration=5)
            rx_avg += stats.rx_pps
        return rx_avg / (repetitions * 1_000_000)

    def _produce_stats_table(self, test_parameters: list[dict[str, int | float | str]]) -> None:
        """Print the results table and write the results to the performance JSON.

        Args:
            test_parameters: The test parameters, including the measured MPPS.
        """
        header = f"{'Stlist':>8} | {'Frame Size':>12} | {'Real MPPS':>12} | {'Expected MPPS':>14}"
        print("-" * len(header))
        print(header)
        print("-" * len(header))
        for params in test_parameters:
            print(f"{params['stlist']:>8} | {params['frame_size']:>12} | ", end="")
            print(f"{params['measured_mpps']:>12} | {params['expected_mpps']:>14}")
            print("-" * len(header))

        write_performance_json({"results": test_parameters})

    @perf_test
    def eventdev_pipeline_perf(self) -> None:
        """Eventdev pipeline performance test.

        Steps:
            * Launch dpdk-test-eventdev with the software event device and an Ethernet device as
              the producer.
            * Send traffic at each configured frame size.

        Verify:
            * Measured MPPS is within the delta tolerance of the expected MPPS.
        """
        for params in self.config.test_parameters:
            with Eventdev(
                test=self.config.test,
                num_workers=self.config.num_workers,
                stlist=str(params["stlist"]),
                pool_sz=self.config.pool_size,
            ):
                time.sleep(self.config.link_up_delay)
                params["measured_mpps"] = round(
                    self._transmit(int(params["frame_size"]), repetitions=5), 3
                )
            params["performance_delta"] = round(
                (float(params["measured_mpps"]) - float(params["expected_mpps"]))
                / float(params["expected_mpps"]),
                3,
            )
            params["pass"] = float(params["performance_delta"]) >= -self.config.delta_tolerance

        self._produce_stats_table(self.config.test_parameters)

        for params in self.config.test_parameters:
            verify(
                params["pass"] is True,
                f"""Packets forwarded is less than {(1 - self.config.delta_tolerance) * 100}%
                of the expected baseline.
                Stlist = {params["stlist"]}
                Frame size = {params["frame_size"]}
                Measured MPPS = {params["measured_mpps"]}
                Expected MPPS = {params["expected_mpps"]}""",
            )
