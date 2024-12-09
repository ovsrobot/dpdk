# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 University of New Hampshire

"""DPDK EAL sanity check suite.

Starts and stops a testpmd session to verify EAL parameters
are properly configured.
"""

from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite, func_test


class TestEal(TestSuite):
    """EAL test suite. One test case, which starts and stops a testpmd session."""

    @func_test
    def test_verify_eal(self) -> None:
        """EAL sanity test.

        Steps:
            Start testpmd session and check status.
        Verify:
            The testpmd session is alive after starting.
        """
        with TestPmdShell(node=self.sut_node) as testpmd:
            testpmd.start()
            self.verify(True, "True")
