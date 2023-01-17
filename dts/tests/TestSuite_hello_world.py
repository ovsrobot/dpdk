# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

"""
DPDK Test suite.
Test HelloWorld example.
"""

from framework.test_suite import TestSuite
from framework.testbed_model import (
    LogicalCoreAmount,
    LogicalCoreAmountFilter,
    LogicalCoreList,
)


class TestHelloWorld(TestSuite):
    def set_up_suite(self) -> None:
        """
        Run at the start of each test suite.
        hello_world Prerequisites:
            helloworld build pass
        """
        self.app_helloworld_path = self.sut_node.build_dpdk_app("helloworld")

    def test_hello_world_single_core(self) -> None:
        """
        Run hello world on single lcores
        Only received hello message from core0
        """

        # get the mask for the first core
        lcore_amount = LogicalCoreAmount(1, 1, 1)
        lcores = LogicalCoreAmountFilter(self.sut_node.lcores, lcore_amount).filter()
        eal_para = self.sut_node.create_eal_parameters(
            lcore_filter_specifier=lcore_amount
        )
        result = self.sut_node.run_dpdk_app(self.app_helloworld_path, eal_para)
        self.verify(
            f"hello from core {int(lcores[0])}" in result.stdout,
            f"EAL not started on lcore{lcores[0]}",
        )

    def test_hello_world_all_cores(self) -> None:
        """
        Run hello world on all lcores
        Received hello message from all lcores
        """

        # get the maximum logical core number
        eal_para = self.sut_node.create_eal_parameters(
            lcore_filter_specifier=LogicalCoreList(self.sut_node.lcores)
        )
        result = self.sut_node.run_dpdk_app(self.app_helloworld_path, eal_para, 50)
        for lcore in self.sut_node.lcores:
            self.verify(
                f"hello from core {int(lcore)}" in result.stdout,
                f"EAL not started on lcore{lcore}",
            )
