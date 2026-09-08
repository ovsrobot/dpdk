# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2026 University of New Hampshire

"""EventDev pipeline performance test suite.

Measures packet forwarding throughput (MPPS) using dpdk-test-eventdev pipeline mode.
"""

from dataclasses import dataclass

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from api.capabilities import (
    LinkTopology,
    requires_link_topology,
)
from api.packet import assess_performance_by_packet
from api.test import verify, write_performance_json
from framework.params import Option, Params, TextArgument
from framework.remote_session.dpdk_shell import DPDKShell
from framework.test_suite import BaseConfig, TestSuite, perf_test


@dataclass(kw_only=True)
class EventDevParams(Params):

    test: str | None = TextArgument("--test")
    prod_type_ethdev: bool = Option("--prod_type_ethdev")
    stlist: str | None = TextArgument("--stlist")
    wlcores: str | None = TextArgument("--wlcores")
    pool_sz: int | None = TextArgument("--pool-sz")


class Config(BaseConfig):

    frame_sizes: list[int] = [64, 128, 256, 512, 1024, 1518]
    num_descriptors: int = 1024
    traffic_duration: int = 5
    pool_size: int = 16384
    delta_tolerance: float = 0.05
    expected_mpps: dict[int, float] = {
        64: 14.8,
        128: 12.0,
        256: 8.5,
        512: 4.5,
        1024: 2.3,
        1518: 1.5,
    }


@requires_link_topology(LinkTopology.TWO_LINKS)
class TestEventdevPipelinePerf(TestSuite):

    config: Config

    def set_up_suite(self) -> None:

        self.delta_tolerance = self.config.delta_tolerance

    def _transmit(self, frame_size: int, repetitions: int = 5) -> float:
        padding = max(0, frame_size - len(Ether() / IP()))
        packet = Ether() / IP() / Raw(b"X" * padding)

        total_mpps = 0.0
        for _ in range(repetitions):
            stats = assess_performance_by_packet(
                packet=packet,
                duration=self.config.traffic_duration,
            )
            total_mpps += stats.rx_mpps

        return total_mpps / repetitions

    def _produce_stats_table(self, test_parameters: list[dict[str, int | float]]) -> None:
    
        header = f"{'Frame Size':>12} | {'TXD/RXD':>12} | {'Real MPPS':>12} | {'Expected MPPS':>14}"
        print("-" * len(header))
        print(header)
        print("-" * len(header))
        for params in test_parameters:

            print(f"{params['frame_size']:>12} | {params['num_descriptors']:>12} | ", end="")
            print(f"{params['measured_mpps']:>12} | {params['expected_mpps']:>14}")
            print("-" * len(header))

        write_performance_json({"results": test_parameters})

    @perf_test
    def test_perf_eventdev_pipeline_1ports_atomic_performance(self) -> None:
        results = []

        worker_core = str(self.sut_node.lcores[1].id)

        eventdev_params = EventDevParams(

            test="pipeline_atq",
            prod_type_ethdev=True,
            stlist="a",
            wlcores=worker_core,
            pool_sz=self.config.pool_size,
        )

        with self.sut_node.create_interactive_shell(

            DPDKShell,
            app_name="dpdk-test-eventdev",
            app_params=eventdev_params,
            eal_params=Params(vdev="event_sw0"),
            privileged=True,
        ) as eventdev_app:
            for frame_size in self.config.frame_sizes:
                
                measured_mpps = round(self._transmit(frame_size=frame_size, repetitions=5), 2)
                expected_mpps = self.config.expected_mpps.get(frame_size, 0.0)
                passed = measured_mpps >= (expected_mpps * (1 - self.delta_tolerance))

                results.append(
                    {
                        "frame_size": frame_size,
                        "num_descriptors": self.config.num_descriptors,
                        "measured_mpps": measured_mpps,
                        "expected_mpps": expected_mpps,
                        "pass": passed,
                    }
                )

        self._produce_stats_table(results)

        for result in results:

            expected_baseline = result["expected_mpps"] * (1 - self.delta_tolerance)
            verify(
                result["pass"],
                f"Measured MPPS ({result['measured_mpps']:.2f}) for frame size {result['frame_size']} "
                f"is below expected baseline ({expected_baseline:.2f}).",
            )
