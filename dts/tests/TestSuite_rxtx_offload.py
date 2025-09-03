# Copyright(c) 2025 University of New Hampshire

"""Rx Tx offload test suite.

Test the testpmd feature of configuring Rx and Tx offloads
"""

from framework.remote_session.testpmd_shell import (
    NicCapability,
    RxTxArgFlag,
    TestPmdShell,
)
from framework.test_suite import TestSuite, func_test
from framework.testbed_model.capability import requires


@requires(NicCapability.TX_OFFLOAD_MBUF_FAST_FREE)
class TestRxTxOffload(TestSuite):
    """RX/TX offload test suite."""

    def check_port_config(
        self,
        testpmd: TestPmdShell,
        offload: str,
        verify: bool,
        port_id: int = 0,
    ) -> bool:
        """Checks that the current port configuration matches the given offload.

        Args:
            testpmd: The current testpmd shell session to send commands to.
            offload: The expected configuration of the given port.
            verify: Whether to verify the result of call to testpmd.
            port_id: Id of the port to check.

        Returns:
            Whether current configuration matches given offload.
        """
        output = testpmd.get_rxtx_offload_config(RxTxArgFlag.TX, verify, port_id, 0)
        return offload in output["port"] or (
            offload == "NULL" and "MBUF_FAST_FREE" not in output["port"]
        )

    def check_queue_config(
        self,
        testpmd: TestPmdShell,
        offload: list[str],
        verify: bool,
        port_id: int = 0,
        num_queues: int = 0,
    ) -> bool:
        """Checks that the queue configuration matches the given offload.

        Args:
            testpmd: The current testpmd shell session to send commands to.
            offload: The expected configuration of the queues, each index corresponds
                to the queue id.
            verify: Whether to verify commands sent to testpmd.
            port_id: The port of which the queues reside.
            num_queues: The number of queues to check.

        Returns:
            Whether current configuration matches given offload
        """
        output = testpmd.get_rxtx_offload_config(RxTxArgFlag.TX, verify, port_id, num_queues)
        for i in range(0, num_queues):
            if not (
                offload[i] in output[i]
                or (offload[i] == "NULL" and "MBUF_FAST_FREE" not in output[i])
            ):
                return False
        return True

    @func_test
    def test_mbuf_fast_free_configurations(self) -> None:
        """Ensure mbuf_fast_free can be configured with testpmd.

        Steps:
            Start up testpmd shell.
            Toggle mbuf_fast_free on.
            Toggle mbuf_fast_free off.

        Verify:
            Mbuf_fast_free starts disabled.
            Mbuf_fast_free can be configured on.
            Mbuf_fast_free can be configured off.
        """
        with TestPmdShell() as testpmd:
            verify: bool = True
            port_id: int = 0
            num_queues: int = 4
            queue_off: list[str] = []
            queue_on: list[str] = []
            mbuf_on = "MBUF_FAST_FREE"
            mbuf_off = "NULL"

            for _ in range(0, num_queues):
                queue_off.append(mbuf_off)
                queue_on.append(mbuf_on)

            testpmd.set_ports_queues(num_queues)
            testpmd.start_all_ports()

            # Ensure mbuf_fast_free is disabled by default on port and queues
            self.verify(
                self.check_port_config(testpmd, mbuf_off, verify, port_id),
                "Mbuf_fast_free enabled on port start",
            )
            self.verify(
                self.check_queue_config(testpmd, queue_off, verify, port_id, num_queues),
                "Mbuf_fast_free enabled on queue start",
            )

            # Enable mbuf_fast_free per queue and verify
            testpmd.set_all_queues_mbuf_fast_free(True, verify, port_id, num_queues)
            self.verify(
                self.check_port_config(testpmd, mbuf_off, verify, port_id),
                "Port configuration changed without call",
            )
            self.verify(
                self.check_queue_config(testpmd, queue_on, verify, port_id, num_queues),
                "Queues failed to enable mbuf_fast_free",
            )

            # Enable mbuf_fast_free per port and verify
            testpmd.set_port_mbuf_fast_free(True, verify, port_id)
            self.verify(
                self.check_port_config(testpmd, mbuf_on, verify, port_id),
                "Port failed to enable mbuf_fast_free",
            )

            # Disable mbuf_fast_free per queue and verify
            testpmd.set_all_queues_mbuf_fast_free(False, verify, port_id, num_queues)
            self.verify(
                self.check_port_config(testpmd, mbuf_on, verify, port_id),
                "Port configuration changed without call",
            )
            self.verify(
                self.check_queue_config(testpmd, queue_off, verify, port_id, num_queues),
                "Queues failed to disable mbuf_fast_free",
            )

            # Disable mbuf_fast_free per port and verify
            testpmd.set_port_mbuf_fast_free(False, verify, port_id)
            self.verify(
                self.check_port_config(testpmd, mbuf_off, verify, port_id),
                "Port failed to disable mbuf_fast_free",
            )
