# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""Cryptodev-pmd non-interactive shell.

Typical usage example in a TestSuite::

    cryptodev = CryptodevPmd(CryptoPmdParams)
    stats = cryptodev.run_app()
    cryptodev.print_stats(stats)
"""

import re
from typing import TYPE_CHECKING, Any

from typing_extensions import Unpack

from api.cryptodev.config import CryptoPmdParams, TestType
from api.cryptodev.types import (
    CryptodevResults,
    LatencyResults,
    PmdCyclecountResults,
    ThroughputResults,
    VerifyResults,
)
from framework.config.node import PortConfig
from framework.context import get_ctx
from framework.exception import RemoteCommandExecutionError, SkippedTestException
from framework.testbed_model.cpu import LogicalCoreList
from framework.testbed_model.port import Port

if TYPE_CHECKING:
    from framework.params.types import CryptoPmdParamsDict
from pathlib import PurePath

from framework.remote_session.dpdk import DPDKBuildEnvironment


class Cryptodev:
    """non-interactive cryptodev application.

    Attributes:
        _dpdk: The dpdk runtime to run the cryptodev app on.
        _app_params: A combination of application and EAL parameters.
    """

    _dpdk: DPDKBuildEnvironment
    _app_params: dict[str, Any]

    def __init__(self, **app_params: Unpack["CryptoPmdParamsDict"]) -> None:
        """Initialize the cryptodev application.

        Args:
            app_params: The application parameters as keyword arguments.
        """
        self._app_params = {}
        for k, v in app_params.items():
            if v is not None:
                self._app_params[k] = (
                    self.vector_directory.joinpath(str(v)) if k == "test_file" else v
                )
        self._dpdk = get_ctx().dpdk_build
        self._path = self._dpdk.get_app("test-crypto-perf")

    @property
    def path(self) -> PurePath:
        """Get the path to the cryptodev application.

        Returns:
            The path to the cryptodev application.
        """
        return PurePath(self._path)

    @property
    def vector_directory(self) -> PurePath:
        """Get the path to the cryptodev vector files.

        Returns:
            The path to the cryptodev vector files.
        """
        return self._dpdk.remote_dpdk_tree_path.joinpath("app/test-crypto-perf/data/")

    @staticmethod
    def _print_latency_stats(
        ptest: type[CryptodevResults], results: LatencyResults, print_title: bool
    ) -> None:
        """Print the stats table after a latency test has been run.

        Args:
            ptest: The type of performance test being run.
            results: The latency results to print.
            print_title: Whether to print the title of the table.
        """
        table_header = ["", "min", "max", "avg", "total"]
        element_len = max(len(metric) for metric, _ in results) + 3
        border_len = (element_len + 1) * (len(table_header))

        if print_title:
            print(f"{f'{ptest.__name__}'.center(border_len)}")
            print("=" * border_len)
        print_header = True
        for metric, data in results:
            # Print presets
            if metric in ("buffer_size", "burst_size"):
                print(f"{metric}: {data}")
                continue
            elif "min" in metric:
                if print_header:
                    print("=" * border_len)
                    for stat in table_header:
                        print(f"|{stat:^{element_len}}", end="")
                    print(f"|\n{'=' * border_len}|", end="")
                    print_header = False
                # Fill table with data
                print(f"\n|{metric.replace('min_', '', 1):<{element_len}}|", end="")
            print(f"{data:<{element_len}}|", end="")
        print(f"\n{'=' * border_len}")

    @staticmethod
    def _print_stats_helper(
        ptest: type[CryptodevResults],
        results: CryptodevResults,
        border_len: int,
        print_header: bool,
    ) -> None:
        """Print the stats table after a throughput, verify, or pmd_cyclecount test.

        Args:
            ptest: The type of performance test being run.
            results: The results to print.
            border_len: The width of the table in characters.
            print_header: Whether to print the title of the table.
        """
        if isinstance(results, LatencyResults):
            return Cryptodev._print_latency_stats(ptest, results, print_header)
        if print_header:
            print(f"{f'{ptest.__name__}'.center(border_len)}")
            print("=" * border_len)
            for metric, data in results:
                print(f"|{metric:<{len(metric) + 3}}", end="")
            print(f"|\n{'=' * border_len}")
        for metric, data in results:
            print(f"|{data:<{len(metric) + 3}}", end="")
        print(f"|\n{'=' * border_len}")

    @staticmethod
    def print_stats(results: list[CryptodevResults]) -> None:
        """Print the statistics of the most recent run of the cryptodev application.

        Raises:
            ValueError: If stats are printed before the application has been run.
        """
        print_header = True
        if len(results) == 0:
            raise ValueError("No results to print.")
        border_len = sum(len(key) + 4 for key in vars(results[0]))
        for result in results:
            Cryptodev._print_stats_helper(type(result), result, border_len, print_header)
            print_header = False

    def run_app(self) -> list[CryptodevResults]:
        """Run the cryptodev application with the current parameters.

        Raises:
            SkippedTestException: If the device type is not supported on the main session.
            RemoteCommandExecutionError: If there is an error running the command.
            ValueError: If an invalid performance test type is specified.

        Returns:
            list[CryptodevResults]: The list of parsed results for the cryptodev application.
        """
        crypto_ports = [
            Port(
                self._dpdk._node,
                PortConfig(
                    name="crypto_port0", pci="0000:03:01.0", os_driver="", os_driver_for_dpdk=""
                ),
            )
        ]
        send_command = f"{self.path} --socket-mem 2048,0 {
            CryptoPmdParams(
                lcore_list=LogicalCoreList([9,10]),
                allowed_ports= crypto_ports,
                memory_channels=6,
                **self._app_params,
            )
        }"

        try:
            # run cryptodev app on the sut node
            result = self._dpdk._node.main_session.send_command(
                send_command, privileged=True, timeout=120
            )
        except RemoteCommandExecutionError as e:
            # skip test when device or algorithm is not supported
            if "No crypto devices type" in e._command_stderr:
                print(
                    f"Skipping test: {self._app_params['devtype']}\
                        type not supported on this session."
                )
                raise SkippedTestException(
                    f"Could not run cryptodev application with devtype\
                        {self._app_params['devtype']}"
                )
            raise e

        regex = r"^\s+\d+.*$"
        parser_options = re.MULTILINE
        parser: type[CryptodevResults]

        match self._app_params["ptest"]:
            case TestType.throughput:
                parser = ThroughputResults
            case TestType.latency:
                regex = r"total operations:.*time[^\n]*"
                parser_options |= re.DOTALL
                parser = LatencyResults
            case TestType.pmd_cyclecount:
                parser = PmdCyclecountResults
            case TestType.verify:
                parser = VerifyResults
            case _:
                raise ValueError(f"Ptest {self._app_params['ptest']} is not a valid option")

        return [parser.parse(line) for line in re.findall(regex, result.stdout, parser_options)]
