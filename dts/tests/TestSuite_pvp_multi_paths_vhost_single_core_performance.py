# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""Vhost-user single-core forwarding performance test suite.

This suite measures the packet forwarding performance of DPDK's vhost-user PMD running on a
single CPU core in a Physical-Virtual-Physical (PVP) topology. Performance is evaluated across
multiple virtio-user backend options, including packed versus split ring formats, in-order packet
processing, mergeable buffers, and SIMD vectorization. Test cases are parameterized using
combinations of frame sizes, descriptor ring sizes, and target MPPS baselines specified in the
test configuration. High-speed traffic is injected from an external generator through SUT physical
interfaces, routed through Vhost and Virtio loops, and returned to the generator to measure
aggregate MPPS.
"""

from typing import cast

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from api.capabilities import (
    LinkTopology,
    requires_link_topology,
)
from api.packet import assess_performance_by_packet
from api.test import get_current_test_case_name, verify, write_performance_json
from api.testpmd import TestPmd
from api.testpmd.config import (
    Params,
    PortTopology,
    RXRingParams,
    SimpleForwardingModes,
    TXRingParams,
)
from framework.params.eal import VirtualDevice
from framework.params.types import LogicalCoreList, RSSSetting, TestPmdParamsDict
from framework.test_suite import BaseConfig, TestSuite, perf_test


class Config(BaseConfig):
    """Performance test metrics."""

    test_parameters: list[dict[str, int | float]] = [
        {"frame_size": 64, "num_descriptors": 1024, "expected_mpps": 1.00},
        {"frame_size": 128, "num_descriptors": 1024, "expected_mpps": 1.00},
        {"frame_size": 256, "num_descriptors": 1024, "expected_mpps": 1.00},
        {"frame_size": 512, "num_descriptors": 1024, "expected_mpps": 1.00},
        {"frame_size": 1024, "num_descriptors": 1024, "expected_mpps": 1.00},
        {"frame_size": 1518, "num_descriptors": 1024, "expected_mpps": 1.00},
    ]
    delta_tolerance: float = 0.05


@requires_link_topology(LinkTopology.TWO_LINKS)
class TestPvpMultiPathsVhostSingleCorePerformance(TestSuite):
    """pvp multi paths vhost single core performance test suite."""

    config: Config

    def set_up_suite(self):
        """Assign test parameters."""
        self.test_parameters = self.config.test_parameters
        self.delta_tolerance = self.config.delta_tolerance

    def set_up_test_case(self):
        """Delete stale vhost-user Unix domain socket files."""
        self._ctx.sut_node.main_session.send_command("rm -rf /tmp/vhost-net*", privileged=True)

    def _transmit(
        self, vhost: TestPmd, virtio: TestPmd, frame_size: int, repetitions: int = 1
    ) -> float:
        """Transmit packets using testpmd instances and compute average MPPS.

        Args:
            vhost: the running vhost testpmd shell.
            virtio: the running virtio testpmd shell.
            frame_size: The size of the frame to transmit.
            repetitions: The number of times to rerun the transmission.

        Returns:
            The MPPS (millions of packets per second) forwarded by the SUT.
        """
        assert repetitions > 0, "Invalid number of repetitions given."
        # Build packet with dummy values, and account for the 14B and 20B Ether and IP headers
        packet = (
            Ether(src="52:00:00:00:00:00")
            / IP(src="1.2.3.4", dst="192.18.1.0")
            / Raw(load="x" * (frame_size - 14 - 20))
        )

        vhost.start()
        virtio.start()
        rx_avg = 0.0

        for _ in range(repetitions):
            # Transmit for 5 seconds.
            stats = assess_performance_by_packet(packet=packet, duration=5)
            rx_avg += stats.rx_pps
        return rx_avg / (repetitions * 1_000_000)

    def _create_and_transmit(
        self,
        ring_format: int,
        in_order: int,
        buffers: int,
        vectorized: int,
        extra_args: TestPmdParamsDict,
    ) -> None:
        """Create testpmd instances with specified params and send traffic."""
        sut_dpdk_driver = self._ctx.sut_node.config.ports[0].os_driver_for_dpdk
        vhost_user_vdev = VirtualDevice("net_vhost0,iface=/tmp/vhost-net,queues=1")
        virtio_user_vdev = VirtualDevice(
            "net_virtio_user0,"
            "mac=00:11:22:33:44:10,"
            "path=/tmp/vhost-net,"
            "queues=1,"
            f"packed_vq={ring_format},"
            f"mrg_rxbuf={buffers},"
            f"in_order={in_order},"
            f"vectorized={vectorized}"
        )

        for params in self.test_parameters:
            frame_size = params["frame_size"]
            num_descriptors = params["num_descriptors"]

            default_args: TestPmdParamsDict = {
                "tx_ring": TXRingParams(descriptors=num_descriptors),
                "rx_ring": RXRingParams(descriptors=num_descriptors),
            }

            if sut_dpdk_driver == "mlx5_core":
                default_args["burst"] = 64
                default_args["mbcache"] = 512
            elif sut_dpdk_driver == "i40e":
                default_args["rx_queues"] = 1
                default_args["tx_queues"] = 1

            vhost_params: TestPmdParamsDict = {
                "prefix": "vhost",
                "allowed_ports": [],
                "memory_channels": 4,
                "port_topology": PortTopology.chained,
                "vdevs": [vhost_user_vdev],
                "lcore_list": LogicalCoreList([1, 2]),
                "nb_cores": 1,
                **default_args,
            }

            virtio_params: TestPmdParamsDict = {
                "prefix": "virtio",
                "no_pci": True,
                "memory_channels": 4,
                "allowed_ports": [],
                "vdevs": [virtio_user_vdev],
                "lcore_list": LogicalCoreList([3, 4, 5]),
                "nb_cores": 2,
                **extra_args,
                **default_args,
            }

            with (
                TestPmd(**vhost_params) as vhost,
                TestPmd(**virtio_params) as virtio,
            ):
                vhost.set_forward_mode(SimpleForwardingModes.mac)
                virtio.set_forward_mode(SimpleForwardingModes.io)
                vhost.set_portlist([0, 2, 1])

                params["measured_mpps"] = round(
                    self._transmit(vhost, virtio, frame_size, repetitions=5), 3
                )
                params["performance_delta"] = round(
                    (float(params["measured_mpps"]) - float(params["expected_mpps"]))
                    / float(params["expected_mpps"]),
                    3,
                )
                params["pass"] = float(params["performance_delta"]) >= -self.delta_tolerance

        self._produce_stats_table(self.test_parameters)
        for params in self.test_parameters:
            verify(
                params["pass"] is True,
                f"""Packets forwarded is less than {(1 - self.delta_tolerance) * 100}%
                of the expected baseline.
                Measured MPPS = {params["measured_mpps"]}
                Expected MPPS = {params["expected_mpps"]}""",
            )

    def _produce_stats_table(self, test_parameters: list[dict[str, int | float]]) -> None:
        """Display performance results in table format and write to structured JSON file.

        Args:
            test_parameters: The expected and real stats per set of test parameters.
        """
        test_case = get_current_test_case_name()
        header = f"{'Frame Size':>12} | {'TXD/RXD':>12} | {'Real MPPS':>12} | {'Expected MPPS':>14}"
        print(f"{test_case} Results:")
        print("-" * len(header))
        print(header)
        print("-" * len(header))
        for params in test_parameters:
            print(f"{params['frame_size']:>12} | {params['num_descriptors']:>12} | ", end="")
            print(f"{params['measured_mpps']:>12} | {params['expected_mpps']:>14}")
            print("-" * len(header))

        write_performance_json({"results": test_parameters})

    @perf_test
    def test_perf_vhost_single_core_virtio11_mergeable(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: ring_format=1, buffers=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {
            "tx_offloads": 0,
            "enable_hw_vlan_strip": True,
            "rss": cast(RSSSetting, RSSSetting.SetIPOnly()),
        }
        self._create_and_transmit(
            ring_format=1,
            buffers=1,
            in_order=0,
            vectorized=0,
            extra_args=extra_args,
        )

    @perf_test
    def test_perf_vhost_single_core_virtio11_non_mergeable(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: ring_format=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {
            "tx_offloads": 0,
            "enable_hw_vlan_strip": True,
            "rss": cast(RSSSetting, RSSSetting.SetIPOnly()),
        }
        self._create_and_transmit(
            ring_format=1,
            buffers=0,
            in_order=0,
            vectorized=0,
            extra_args=extra_args,
        )

    @perf_test
    def test_perf_vhost_single_core_virtio_inorder_mergeable(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: buffers=1, in_order=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {
            "tx_offloads": 0,
            "enable_hw_vlan_strip": True,
            "rss": cast(RSSSetting, RSSSetting.SetIPOnly()),
        }
        self._create_and_transmit(
            ring_format=0,
            buffers=1,
            in_order=1,
            vectorized=0,
            extra_args=extra_args,
        )

    @perf_test
    def test_perf_vhost_single_core_virtio_inorder_nonmergeable(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: in_order=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {
            "tx_offloads": 0,
            "enable_hw_vlan_strip": True,
            "rss": cast(RSSSetting, RSSSetting.SetIPOnly()),
        }
        self._create_and_transmit(
            ring_format=0,
            buffers=0,
            in_order=1,
            vectorized=0,
            extra_args=extra_args,
        )

    @perf_test
    def test_perf_vhost_single_core_virtio_mergeable(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: buffers=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {
            "tx_offloads": 0,
            "enable_hw_vlan_strip": True,
            "rss": cast(RSSSetting, RSSSetting.SetIPOnly()),
        }
        self._create_and_transmit(
            ring_format=0,
            buffers=1,
            in_order=0,
            vectorized=0,
            extra_args=extra_args,
        )

    @perf_test
    def test_perf_vhost_single_core_virtio_nonmergeable(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: vectorized=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {
            "tx_offloads": 0,
            "enable_hw_vlan_strip": True,
            "rss": cast(RSSSetting, RSSSetting.SetIPOnly()),
        }
        self._create_and_transmit(
            ring_format=0,
            buffers=0,
            in_order=0,
            vectorized=1,
            extra_args=extra_args,
        )

    @perf_test
    def test_perf_vhost_single_core_virtio_vectorized(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: vectorized=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        self._create_and_transmit(
            ring_format=0,
            buffers=0,
            in_order=0,
            vectorized=1,
            extra_args={},
        )

    @perf_test
    def test_perf_vhost_single_core_virtio11_inorder_mergeable(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: ring_format=1, buffers=1, in_order=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {
            "tx_offloads": 0,
            "enable_hw_vlan_strip": True,
            "rss": cast(RSSSetting, RSSSetting.SetIPOnly()),
        }
        self._create_and_transmit(
            ring_format=1,
            buffers=1,
            in_order=1,
            vectorized=0,
            extra_args=extra_args,
        )

    @perf_test
    def test_perf_vhost_single_core_virtio11_inorder_nonmergeable(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: ring_format=1, in_order=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {"rss": cast(RSSSetting, RSSSetting.SetIPOnly())}
        self._create_and_transmit(
            ring_format=1,
            buffers=0,
            in_order=1,
            vectorized=0,
            extra_args=extra_args,
        )

    @perf_test
    def test_perf_vhost_single_core_virtio11_vectorized(self) -> None:
        """Validate expected single core forwarding performance.

        Steps:
            * Set TestPMD virtio parameters: ring_format=1, in_order=1, vectorized=1.
            * Create a packet according to the frame size specified in the test config.
            * Transmit from the traffic generator's ports 0 and 1 at above the expect.
            * Forward on TestPMD's interfaces 0 and 1 with 1 core.

        Verify:
            * The resulting MPPS forwarded is greater than expected_mpps*(1-delta_tolerance).
        """
        extra_args: TestPmdParamsDict = {
            "rss": cast(RSSSetting, RSSSetting.SetIPOnly()),
            "other_eal_param": Params.from_str("--force-max-simd-bitwidth=512"),
        }
        self._create_and_transmit(
            ring_format=1,
            buffers=0,
            in_order=1,
            vectorized=1,
            extra_args=extra_args,
        )
