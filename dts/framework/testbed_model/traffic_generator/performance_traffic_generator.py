"""Performance testing capable traffic generatiors."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from scapy.packet import Packet

from framework.testbed_model.traffic_generator.traffic_generator import TrafficGenerator


@dataclass(slots=True)
class PerformanceTrafficStats(ABC):
    """Data structure for stats offered by a given traffic generator."""

    frame_size: int


class PerformanceTrafficGenerator(TrafficGenerator):
    """An Abstract Base Class for all performance-oriented traffic generators.

    Provides an intermediary interface for performance-based traffic generator.
    """

    _test_stats: list[PerformanceTrafficStats]

    @property
    def is_capturing(self) -> bool:
        """Used for synchronization."""
        return False

    @property
    def last_results(self) -> PerformanceTrafficStats | None:
        """Get the latest set of results from TG instance.

        Returns:
            The most recent set of traffic statistics.
        """
        return self._test_stats.pop(0)

    def generate_traffic_and_stats(
        self,
        packet: Packet,
        duration: float,  # Default of 60 (in seconds).
    ) -> PerformanceTrafficStats:
        """Send packet traffic and acquire associated statistics."""
        return self._calculate_traffic_stats(packet, duration, self._generate_traffic)

    def setup(self, ports):
        """Preliminary port setup prior to TG execution."""
        for port in self._tg_node.ports:
            self._tg_node.main_session.configure_port_mtu(2000, port)

    @abstractmethod
    def _calculate_traffic_stats(
        self, packet: Packet, duration: float, traffic_gen_callback: Callable[[Packet, float], str]
    ) -> PerformanceTrafficStats:
        """Calculate packet traffic stats based on TG output."""

    @abstractmethod
    def _generate_traffic(self, packet: Packet, duration: float) -> str:
        """Implementation for :method:`generate_traffic_and_stats`."""
