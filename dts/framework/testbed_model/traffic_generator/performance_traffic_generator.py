"""Traffic generators for performance tests which can generate a high number of packets."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from scapy.packet import Packet

from framework.testbed_model.topology import Topology

from .traffic_generator import TrafficGenerator


@dataclass(slots=True)
class PerformanceTrafficStats(ABC):
    """Data structure to store performance statistics for a given test run.

    Attributes:
        frame_size: The total length of the frame
        tx_pps: Recorded tx packets per second
        tx_cps: Recorded tx connections per second
        tx_bps: Recorded tx bytes per second
        rx_pps: Recorded rx packets per second
        rx_bps: Recorded rx bytes per second
    """

    frame_size: int

    tx_pps: float
    tx_cps: float
    tx_bps: float

    rx_pps: float
    rx_bps: float


class PerformanceTrafficGenerator(TrafficGenerator):
    """An abstract base class for all performance-oriented traffic generators.

    Provides an intermediary interface for performance-based traffic generator.
    """

    @abstractmethod
    def calculate_traffic_and_stats(
        self,
        packet: Packet,
        send_mpps: int,
        duration: float,
    ) -> PerformanceTrafficStats:
        """Send packet traffic and acquire associated statistics.

        Args:
        packet: The packet to send.
        send_mpps: The millions packets per second send rate.
        duration: Performance test duration (in seconds).

        Returns:
            Performance statistics of the generated test.
        """

    def setup(self, topology: Topology) -> None:
        """Overrides :meth:`.traffic_generator.TrafficGenerator.setup`."""
        for port in self._tg_node.ports:
            self._tg_node.main_session.configure_port_mtu(2000, port)
