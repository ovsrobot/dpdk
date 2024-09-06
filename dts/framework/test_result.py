# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.
# Copyright(c) 2023 University of New Hampshire

r"""Record and process DTS results.

The results are recorded in a hierarchical manner:

    * :class:`DTSResult` contains
    * :class:`TestRunResult` contains
    * :class:`TestSuiteResult` contains
    * :class:`TestCaseResult`

Each result may contain multiple lower level results, e.g. there are multiple
:class:`TestSuiteResult`\s in an :class:`TestRunResult`.
The results have common parts, such as setup and teardown results, captured in :class:`BaseResult`,
which also defines some common behaviors in its methods.

Each result class has its own idiosyncrasies which they implement in overridden methods.

The :option:`--output` command line argument and the :envvar:`DTS_OUTPUT_DIR` environment
variable modify the directory where the files with results will be stored.
"""

import json
from collections.abc import MutableSequence
from dataclasses import asdict, dataclass
from enum import Enum, auto
from pathlib import Path
from types import FunctionType
from typing import Any, TypedDict

from .config import DPDKBuildInfo, NodeInfo, TestRunConfiguration, TestSuiteConfig
from .exception import DTSError, ErrorSeverity
from .logger import DTSLogger
from .settings import SETTINGS
from .test_suite import TestSuite
from .testbed_model.port import Port


@dataclass(slots=True, frozen=True)
class TestSuiteWithCases:
    """A test suite class with test case methods.

    An auxiliary class holding a test case class with test case methods. The intended use of this
    class is to hold a subset of test cases (which could be all test cases) because we don't have
    all the data to instantiate the class at the point of inspection. The knowledge of this subset
    is needed in case an error occurs before the class is instantiated and we need to record
    which test cases were blocked by the error.

    Attributes:
        test_suite_class: The test suite class.
        test_cases: The test case methods.
    """

    test_suite_class: type[TestSuite]
    test_cases: list[FunctionType]

    def create_config(self) -> TestSuiteConfig:
        """Generate a :class:`TestSuiteConfig` from the stored test suite with test cases.

        Returns:
            The :class:`TestSuiteConfig` representation.
        """
        return TestSuiteConfig(
            test_suite=self.test_suite_class.__name__,
            test_cases=[test_case.__name__ for test_case in self.test_cases],
        )


class Result(Enum):
    """The possible states that a setup, a teardown or a test case may end up in."""

    #:
    PASS = auto()
    #:
    FAIL = auto()
    #:
    ERROR = auto()
    #:
    SKIP = auto()
    #:
    BLOCK = auto()

    def __bool__(self) -> bool:
        """Only PASS is True."""
        return self is self.PASS


class TestCaseResultDict(TypedDict):
    test_case_name: str
    result: str


class TestSuiteResultDict(TypedDict):
    test_suite_name: str
    test_cases: list[TestCaseResultDict]


class TestRunResultDict(TypedDict, total=False):
    compiler_version: str | None
    dpdk_version: str | None
    ports: list[dict[str, Any]] | None
    test_suites: list[TestSuiteResultDict]
    summary: dict[str, Any]


class DtsRunResultDict(TypedDict):
    test_runs: list[TestRunResultDict]
    summary: dict[str, Any]


class FixtureResult:
    """A record that stores the result of a setup or a teardown.

    :attr:`~Result.FAIL` is a sensible default since it prevents false positives (which could happen
    if the default was :attr:`~Result.PASS`).

    Preventing false positives or other false results is preferable since a failure
    is mostly likely to be investigated (the other false results may not be investigated at all).

    Attributes:
        result: The associated result.
        error: The error in case of a failure.
    """

    result: Result
    error: Exception | None = None

    def __init__(
        self,
        result: Result = Result.FAIL,
        error: Exception | None = None,
    ):
        """Initialize the constructor with the fixture result and store a possible error.

        Args:
            result: The result to store.
            error: The error which happened when a failure occurred.
        """
        self.result = result
        self.error = error

    def __bool__(self) -> bool:
        """A wrapper around the stored :class:`Result`."""
        return bool(self.result)


class BaseResult:
    """Common data and behavior of DTS results.

    Stores the results of the setup and teardown portions of the corresponding stage.
    The hierarchical nature of DTS results is captured recursively in an internal list.
    A stage is each level in this particular hierarchy (pre-run or the top-most level,
    test run, test suite and test case.)

    Attributes:
        setup_result: The result of the setup of the particular stage.
        teardown_result: The results of the teardown of the particular stage.
        child_results: The results of the descendants in the results hierarchy.
    """

    setup_result: FixtureResult
    teardown_result: FixtureResult
    child_results: MutableSequence["BaseResult"]

    def __init__(self):
        """Initialize the constructor."""
        self.setup_result = FixtureResult()
        self.teardown_result = FixtureResult()
        self.child_results = []

    def update_setup(self, result: Result, error: Exception | None = None) -> None:
        """Store the setup result.

        If the result is :attr:`~Result.BLOCK`, :attr:`~Result.ERROR` or :attr:`~Result.FAIL`,
        then the corresponding child results in result hierarchy
        are also marked with :attr:`~Result.BLOCK`.

        Args:
            result: The result of the setup.
            error: The error that occurred in case of a failure.
        """
        self.setup_result.result = result
        self.setup_result.error = error

        if result in [Result.BLOCK, Result.ERROR, Result.FAIL]:
            self.update_teardown(Result.BLOCK)
            self._block_result()

    def _block_result(self) -> None:
        r"""Mark the result as :attr:`~Result.BLOCK`\ed.

        The blocking of child results should be done in overloaded methods.
        """

    def update_teardown(self, result: Result, error: Exception | None = None) -> None:
        """Store the teardown result.

        Args:
            result: The result of the teardown.
            error: The error that occurred in case of a failure.
        """
        self.teardown_result.result = result
        self.teardown_result.error = error

    def _get_setup_teardown_errors(self) -> list[Exception]:
        errors = []
        if self.setup_result.error:
            errors.append(self.setup_result.error)
        if self.teardown_result.error:
            errors.append(self.teardown_result.error)
        return errors

    def _get_child_errors(self) -> list[Exception]:
        return [error for child_result in self.child_results for error in child_result.get_errors()]

    def get_errors(self) -> list[Exception]:
        """Compile errors from the whole result hierarchy.

        Returns:
            The errors from setup, teardown and all errors found in the whole result hierarchy.
        """
        return self._get_setup_teardown_errors() + self._get_child_errors()

    def to_dict(self):
        """ """

    def add_result(self, results: dict[str, Any] | dict[str, float]):
        for child_result in self.child_results:
            child_result.add_result(results)


class DTSResult(BaseResult):
    """Stores environment information and test results from a DTS run.

        * Test run level information, such as testbed, compiler version, dpdk version
          and the test suite list,
        * Test suite and test case results,
        * All errors that are caught and recorded during DTS execution.

    The information is stored hierarchically. This is the first level of the hierarchy
    and as such is where the data form the whole hierarchy is collated or processed.

    The internal list stores the results of all test runs.

    Attributes:
        dpdk_version: The DPDK version to record.
    """

    dpdk_version: str | None
    _logger: DTSLogger
    _errors: list[Exception]
    _return_code: ErrorSeverity

    def __init__(self, logger: DTSLogger):
        """Extend the constructor with top-level specifics.

        Args:
            logger: The logger instance the whole result will use.
        """
        super().__init__()
        self.dpdk_version = None
        self._logger = logger
        self._errors = []
        self._return_code = ErrorSeverity.NO_ERR

    def add_test_run(self, test_run_config: TestRunConfiguration) -> "TestRunResult":
        """Add and return the child result (test run).

        Args:
            test_run_config: A test run configuration.

        Returns:
            The test run's result.
        """
        result = TestRunResult(test_run_config)
        self.child_results.append(result)
        return result

    def add_error(self, error: Exception) -> None:
        """Record an error that occurred outside any test run.

        Args:
            error: The exception to record.
        """
        self._errors.append(error)

    def process(self) -> None:
        """Process the data after a whole DTS run.

        The data is added to child objects during runtime and this object is not updated
        at that time. This requires us to process the child data after it's all been gathered.

        The processing gathers all errors and the statistics of test case results.
        """
        self._errors += self.get_errors()
        if self._errors and self._logger:
            self._logger.debug("Summary of errors:")
            for error in self._errors:
                self._logger.debug(repr(error))

        TextSummary(self).save(Path(SETTINGS.output_dir, "results_summary.txt"))
        JsonResults(self).save(Path(SETTINGS.output_dir, "results.json"))

    def get_return_code(self) -> int:
        """Go through all stored Exceptions and return the final DTS error code.

        Returns:
            The highest error code found.
        """
        for error in self._errors:
            error_return_code = ErrorSeverity.GENERIC_ERR
            if isinstance(error, DTSError):
                error_return_code = error.severity

            if error_return_code > self._return_code:
                self._return_code = error_return_code

        return int(self._return_code)

    def to_dict(self) -> DtsRunResultDict:
        def merge_all_results(all_results: list[dict[str, Any]]) -> dict[str, Any]:
            return {key.name: sum(d[key.name] for d in all_results) for key in Result}

        test_runs = [child.to_dict() for child in self.child_results]
        return {
            "test_runs": test_runs,
            "summary": merge_all_results([test_run["summary"] for test_run in test_runs]),
        }


class TestRunResult(BaseResult):
    """The test run specific result.

    The internal list stores the results of all test suites in a given test run.

    Attributes:
        compiler_version: The DPDK build compiler version.
        dpdk_version: The built DPDK version.
        sut_os_name: The operating system of the SUT node.
        sut_os_version: The operating system version of the SUT node.
        sut_kernel_version: The operating system kernel version of the SUT node.
    """

    _config: TestRunConfiguration
    _test_suites_with_cases: list[TestSuiteWithCases]
    _ports: list[Port]
    _sut_info: NodeInfo | None
    _dpdk_build_info: DPDKBuildInfo | None

    def __init__(self, test_run_config: TestRunConfiguration):
        """Extend the constructor with the test run's config.

        Args:
            test_run_config: A test run configuration.
        """
        super().__init__()
        self._config = test_run_config
        self._test_suites_with_cases = []
        self._ports = []
        self._sut_info = None
        self._dpdk_build_info = None

    def add_test_suite(
        self,
        test_suite_with_cases: TestSuiteWithCases,
    ) -> "TestSuiteResult":
        """Add and return the child result (test suite).

        Args:
            test_suite_with_cases: The test suite with test cases.

        Returns:
            The test suite's result.
        """
        result = TestSuiteResult(test_suite_with_cases)
        self.child_results.append(result)
        return result

    @property
    def test_suites_with_cases(self) -> list[TestSuiteWithCases]:
        """The test suites with test cases to be executed in this test run.

        The test suites can only be assigned once.

        Returns:
            The list of test suites with test cases. If an error occurs between
            the initialization of :class:`TestRunResult` and assigning test cases to the instance,
            return an empty list, representing that we don't know what to execute.
        """
        return self._test_suites_with_cases

    @test_suites_with_cases.setter
    def test_suites_with_cases(self, test_suites_with_cases: list[TestSuiteWithCases]) -> None:
        if self._test_suites_with_cases:
            raise ValueError(
                "Attempted to assign test suites to a test run result "
                "which already has test suites."
            )
        self._test_suites_with_cases = test_suites_with_cases

    @property
    def ports(self) -> list[Port]:
        """The list of ports associated with the test run.

        This list stores all the ports that are involved in the test run.
        Ports can only be assigned once, and attempting to modify them after
        assignment will raise an error.

        Returns:
            A list of `Port` objects associated with the test run.
        """
        return self._ports

    @ports.setter
    def ports(self, ports: list[Port]) -> None:
        if self._ports:
            raise ValueError(
                "Attempted to assign ports to a test run result which already has ports."
            )
        self._ports = ports

    @property
    def sut_info(self) -> NodeInfo | None:
        return self._sut_info

    @sut_info.setter
    def sut_info(self, sut_info: NodeInfo) -> None:
        if self._sut_info:
            raise ValueError(
                "Attempted to assign `sut_info` to a test run result which already has `sut_info`."
            )
        self._sut_info = sut_info

    @property
    def dpdk_build_info(self) -> DPDKBuildInfo | None:
        return self._dpdk_build_info

    @dpdk_build_info.setter
    def dpdk_build_info(self, dpdk_build_info: DPDKBuildInfo) -> None:
        if self._dpdk_build_info:
            raise ValueError(
                "Attempted to assign `dpdk_build_info` to a test run result which already "
                "has `dpdk_build_info`."
            )
        self._dpdk_build_info = dpdk_build_info

    def to_dict(self) -> TestRunResultDict:
        results = {result.name: 0 for result in Result}
        self.add_result(results)

        compiler_version = None
        dpdk_version = None

        if self.dpdk_build_info:
            compiler_version = self.dpdk_build_info.compiler_version
            dpdk_version = self.dpdk_build_info.dpdk_version

        return {
            "compiler_version": compiler_version,
            "dpdk_version": dpdk_version,
            "ports": [asdict(port) for port in self.ports] or None,
            "test_suites": [child.to_dict() for child in self.child_results],
            "summary": results,
        }

    def _block_result(self) -> None:
        r"""Mark the result as :attr:`~Result.BLOCK`\ed."""
        for test_suite_with_cases in self._test_suites_with_cases:
            child_result = self.add_test_suite(test_suite_with_cases)
            child_result.update_setup(Result.BLOCK)


class TestSuiteResult(BaseResult):
    """The test suite specific result.

    The internal list stores the results of all test cases in a given test suite.

    Attributes:
        test_suite_name: The test suite name.
    """

    test_suite_name: str
    _test_suite_with_cases: TestSuiteWithCases
    _child_configs: list[str]

    def __init__(self, test_suite_with_cases: TestSuiteWithCases):
        """Extend the constructor with test suite's config.

        Args:
            test_suite_with_cases: The test suite with test cases.
        """
        super().__init__()
        self.test_suite_name = test_suite_with_cases.test_suite_class.__name__
        self._test_suite_with_cases = test_suite_with_cases

    def add_test_case(self, test_case_name: str) -> "TestCaseResult":
        """Add and return the child result (test case).

        Args:
            test_case_name: The name of the test case.

        Returns:
            The test case's result.
        """
        result = TestCaseResult(test_case_name)
        self.child_results.append(result)
        return result

    def to_dict(self) -> TestSuiteResultDict:
        return {
            "test_suite_name": self.test_suite_name,
            "test_cases": [child.to_dict() for child in self.child_results],
        }

    def _block_result(self) -> None:
        r"""Mark the result as :attr:`~Result.BLOCK`\ed."""
        for test_case_method in self._test_suite_with_cases.test_cases:
            child_result = self.add_test_case(test_case_method.__name__)
            child_result.update_setup(Result.BLOCK)


class TestCaseResult(BaseResult, FixtureResult):
    r"""The test case specific result.

    Stores the result of the actual test case. This is done by adding an extra superclass
    in :class:`FixtureResult`. The setup and teardown results are :class:`FixtureResult`\s and
    the class is itself a record of the test case.

    Attributes:
        test_case_name: The test case name.
    """

    test_case_name: str

    def __init__(self, test_case_name: str):
        """Extend the constructor with test case's name.

        Args:
            test_case_name: The test case's name.
        """
        super().__init__()
        self.test_case_name = test_case_name

    def update(self, result: Result, error: Exception | None = None) -> None:
        """Update the test case result.

        This updates the result of the test case itself and doesn't affect
        the results of the setup and teardown steps in any way.

        Args:
            result: The result of the test case.
            error: The error that occurred in case of a failure.
        """
        self.result = result
        self.error = error

    def _get_child_errors(self) -> list[Exception]:
        if self.error:
            return [self.error]
        return []

    def to_dict(self) -> TestCaseResultDict:
        """Convert the test case result to a dictionary."""
        return {"test_case_name": self.test_case_name, "result": self.result.name}

    def add_result(self, results: dict[str, Any]):
        results[self.result.name] += 1

    def _block_result(self) -> None:
        r"""Mark the result as :attr:`~Result.BLOCK`\ed."""
        self.update(Result.BLOCK)

    def __bool__(self) -> bool:
        """The test case passed only if setup, teardown and the test case itself passed."""
        return bool(self.setup_result) and bool(self.teardown_result) and bool(self.result)


class TextSummary:
    def __init__(self, dts_run_result: DTSResult) -> None:
        self._dics_result = dts_run_result.to_dict()
        self._summary = self._dics_result["summary"]
        self._text = ""

    @property
    def _outdent(self) -> str:
        """Appropriate indentation based on multiple test run results."""
        return "\t" if len(self._dics_result["test_runs"]) > 1 else ""

    def save(self, output_path: Path):
        """Save the generated text statistics to a file.

        Args:
            output_path: The path where the text file will be saved.
        """
        if self._dics_result["test_runs"]:
            with open(f"{output_path}", "w") as fp:
                self._init_text()
                fp.write(self._text)

    def _init_text(self):
        if len(self._dics_result["test_runs"]) > 1:
            self._add_test_runs_dics()
            self._add_overall_results()
        else:
            test_run_result = self._dics_result["test_runs"][0]
            self._add_test_run_dics(test_run_result)

    def _add_test_runs_dics(self):
        for idx, test_run_dics in enumerate(self._dics_result["test_runs"]):
            self._text += f"TEST_RUN_{idx}\n"
            self._add_test_run_dics(test_run_dics)
            self._text += "\n"

    def _add_test_run_dics(self, test_run_dics: TestRunResultDict):
        self._add_pass_rate_to_results(test_run_dics["summary"])
        self._add_column(
            DPDK_VERSION=test_run_dics["dpdk_version"],
            COMPILER_VERSION=test_run_dics["compiler_version"],
            **test_run_dics["summary"],
        )

    def _add_pass_rate_to_results(self, results_dics: dict[str, Any]):
        results_dics["PASS_RATE"] = (
            float(results_dics[Result.PASS.name])
            * 100
            / sum(results_dics[result.name] for result in Result)
        )

    def _add_column(self, **rows):
        rows = {k: "N/A" if v is None else v for k, v in rows.items()}
        max_length = len(max(rows, key=len))
        for key, value in rows.items():
            self._text += f"{self._outdent}{key:<{max_length}} = {value}\n"

    def _add_overall_results(self):
        self._text += "OVERALL\n"
        self._add_pass_rate_to_results(self._summary)
        self._add_column(**self._summary)


class JsonResults:
    _dics_result: DtsRunResultDict

    def __init__(self, dts_run_result: DTSResult):
        self._dics_result = dts_run_result.to_dict()

    def save(self, output_path: Path):
        with open(f"{output_path}", "w") as fp:
            json.dump(self._dics_result, fp, indent=4)
