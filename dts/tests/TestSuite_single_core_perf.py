"""Single core performance test suite."""

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite, perf_test


class TestSingleCorePerf(TestSuite):
    """Single core performance test suite."""

    @perf_test
    def test_perf_test(self) -> None:
        """Prototype test case."""
        with TestPmdShell() as testpmd:
            packet = Ether() / IP() / Raw(load="x" * 1484)  # 1518 byte packet.

            testpmd.start()
            stats = self.assess_performance_by_packet(packet, duration=5)
            self.verify(
                stats.tx_expected_bps == 40, "Expected output does not patch recorded output."
            )
