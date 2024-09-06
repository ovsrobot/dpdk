# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2019 Intel Corporation
# Copyright(c) 2022-2023 PANTHEON.tech s.r.o.
# Copyright(c) 2022-2023 University of New Hampshire
# Copyright(c) 2024 Arm Limited

"""Test suite runner module.

The module is responsible for running DTS in a series of stages:

    #. Test run stage,
    #. Build target stage,
    #. Test suite stage,
    #. Test case stage.

The test run and build target stages set up the environment before running test suites.
The test suite stage sets up steps common to all test cases
and the test case stage runs test cases individually.
"""

import os
import sys
from pathlib import Path
from types import FunctionType
from typing import Iterable

from pydantic import ValidationError

from framework.testbed_model.sut_node import SutNode
from framework.testbed_model.tg_node import TGNode

from .config import (
    CUSTOM_CONFIG_TYPES,
    BuildTargetConfiguration,
    Configuration,
    SutNodeConfiguration,
    TestRunConfiguration,
    TestSuiteConfig,
    TGNodeConfiguration,
    load_config,
)
from .exception import (
    BlockingTestSuiteError,
    ConfigurationError,
    SSHTimeoutError,
    TestCaseVerifyError,
)
from .logger import DTSLogger, DtsStage, get_dts_logger
from .settings import SETTINGS
from .test_result import (
    BuildTargetResult,
    DTSResult,
    Result,
    TestCaseResult,
    TestRunResult,
    TestSuiteResult,
    TestSuiteWithCases,
)
from .test_suite import TestCase, TestCaseVariant, TestSuite


class DTSRunner:
    r"""Test suite runner class.

    The class is responsible for running tests on testbeds defined in the test run configuration.
    Each setup or teardown of each stage is recorded in a :class:`~framework.test_result.DTSResult`
    or one of its subclasses. The test case results are also recorded.

    If an error occurs, the current stage is aborted, the error is recorded, everything in
    the inner stages is marked as blocked and the run continues in the next iteration
    of the same stage. The return code is the highest `severity` of all
    :class:`~.framework.exception.DTSError`\s.

    Example:
        An error occurs in a build target setup. The current build target is aborted,
        all test suites and their test cases are marked as blocked and the run continues
        with the next build target. If the errored build target was the last one in the
        given test run, the next test run begins.
    """

    _configuration: Configuration
    _logger: DTSLogger
    _result: DTSResult
    _test_suite_class_prefix: str
    _test_suite_module_prefix: str
    _func_test_case_regex: str
    _perf_test_case_regex: str

    def __init__(self):
        """Initialize the instance with configuration, logger, result and string constants."""
        self._configuration = load_config(SETTINGS.config_file_path)
        self._logger = get_dts_logger()
        if not os.path.exists(SETTINGS.output_dir):
            os.makedirs(SETTINGS.output_dir)
        self._logger.add_dts_root_logger_handlers(SETTINGS.verbose, SETTINGS.output_dir)
        self._result = DTSResult(self._logger)
        self._test_suite_class_prefix = "Test"
        self._test_suite_module_prefix = "tests.TestSuite_"
        self._func_test_case_regex = r"test_(?!perf_)"
        self._perf_test_case_regex = r"test_perf_"

    def run(self) -> None:
        """Run all build targets in all test runs from the test run configuration.

        Before running test suites, test runs and build targets are first set up.
        The test runs and build targets defined in the test run configuration are iterated over.
        The test runs define which tests to run and where to run them and build targets define
        the DPDK build setup.

        The tests suites are set up for each test run/build target tuple and each discovered
        test case within the test suite is set up, executed and torn down. After all test cases
        have been executed, the test suite is torn down and the next build target will be tested.

        In order to properly mark test suites and test cases as blocked in case of a failure,
        we need to have discovered which test suites and test cases to run before any failures
        happen. The discovery happens at the earliest point at the start of each test run.

        All the nested steps look like this:

            #. Test run setup

                #. Build target setup

                    #. Test suite setup

                        #. Test case setup
                        #. Test case logic
                        #. Test case teardown

                    #. Test suite teardown

                #. Build target teardown

            #. Test run teardown

        The test cases are filtered according to the specification in the test run configuration and
        the :option:`--test-suite` command line argument or
        the :envvar:`DTS_TESTCASES` environment variable.
        """
        sut_nodes: dict[str, SutNode] = {}
        tg_nodes: dict[str, TGNode] = {}
        try:
            # check the python version of the server that runs dts
            self._check_dts_python_version()
            self._result.update_setup(Result.PASS)

            # for all test run sections
            for test_run_with_nodes_config in self._configuration.test_runs_with_nodes:
                test_run_config, sut_node_config, tg_node_config = test_run_with_nodes_config
                self._logger.set_stage(DtsStage.test_run_setup)
                self._logger.info(f"Running test run with SUT '{sut_node_config.name}'.")
                test_run_result = self._result.add_test_run(test_run_config)
                test_run_test_suites = self._prepare_test_suites(test_run_config)
                try:
                    test_suites_with_cases = self._get_test_suites_with_cases(
                        test_run_test_suites, test_run_config.func, test_run_config.perf
                    )
                    test_run_result.test_suites_with_cases = test_suites_with_cases
                except Exception as e:
                    self._logger.exception(
                        f"Invalid test suite configuration found: " f"{test_run_test_suites}."
                    )
                    test_run_result.update_setup(Result.FAIL, e)

                else:
                    self._connect_nodes_and_run_test_run(
                        sut_nodes,
                        tg_nodes,
                        sut_node_config,
                        tg_node_config,
                        test_run_config,
                        test_run_result,
                        test_suites_with_cases,
                    )

        except Exception as e:
            self._logger.exception("An unexpected error has occurred.")
            self._result.add_error(e)
            raise

        finally:
            try:
                self._logger.set_stage(DtsStage.post_run)
                for node in (sut_nodes | tg_nodes).values():
                    node.close()
                self._result.update_teardown(Result.PASS)
            except Exception as e:
                self._logger.exception("The final cleanup of nodes failed.")
                self._result.update_teardown(Result.ERROR, e)

        # we need to put the sys.exit call outside the finally clause to make sure
        # that unexpected exceptions will propagate
        # in that case, the error that should be reported is the uncaught exception as
        # that is a severe error originating from the framework
        # at that point, we'll only have partial results which could be impacted by the
        # error causing the uncaught exception, making them uninterpretable
        self._exit_dts()

    def _check_dts_python_version(self) -> None:
        """Check the required Python version - v3.10."""
        if sys.version_info.major < 3 or (
            sys.version_info.major == 3 and sys.version_info.minor < 10
        ):
            self._logger.warning(
                "DTS execution node's python version is lower than Python 3.10, "
                "is deprecated and will not work in future releases."
            )
            self._logger.warning("Please use Python >= 3.10 instead.")

    def _prepare_test_suites(self, test_run_config: TestRunConfiguration) -> list[TestSuiteConfig]:
        if SETTINGS.test_suites:
            test_suites_configs = []
            for selected_test_suite, selected_test_cases in SETTINGS.test_suites:
                if selected_test_suite in test_run_config.test_suites:
                    config = test_run_config.test_suites[selected_test_suite].model_copy()
                    config.test_cases_names = selected_test_cases
                else:
                    try:
                        config = CUSTOM_CONFIG_TYPES[selected_test_suite].make(
                            selected_test_suite, *selected_test_cases
                        )
                    except AssertionError as e:
                        raise ConfigurationError(
                            "Invalid test cases were selected "
                            f"for test suite {selected_test_suite}."
                        ) from e
                    except ValidationError as e:
                        raise ConfigurationError(
                            f"Test suite {selected_test_suite} needs to be explicitly configured "
                            "in order to be selected."
                        ) from e
                test_suites_configs.append(config)
        else:
            # we don't want to modify the original config, so create a copy
            test_suites_configs = [
                config.model_copy() for config in test_run_config.test_suites.get_configs()
            ]

        if not test_run_config.skip_smoke_tests:
            test_suites_configs[:0] = [TestSuiteConfig.make("smoke_tests")]

        return test_suites_configs

    def _get_test_suites_with_cases(
        self,
        test_suite_configs: list[TestSuiteConfig],
        func: bool,
        perf: bool,
    ) -> list[TestSuiteWithCases]:
        """Get test suites with selected cases.

        The test suites with test cases defined in the user configuration are selected
        and the corresponding functions and classes are gathered.

        Args:
            test_suite_configs: Test suite configurations.
            func: Whether to include functional test cases in the final list.
            perf: Whether to include performance test cases in the final list.

        Returns:
            The test suites, each with test cases.
        """
        test_suites_with_cases = []

        for test_suite_config in test_suite_configs:
            test_suite_spec = test_suite_config.test_suite_spec
            test_suite_class = test_suite_spec.class_type

            filtered_test_cases: list[TestCase] = [
                test_case
                for test_case in test_suite_spec.test_cases
                if not test_suite_config.test_cases_names
                or test_case.name in test_suite_config.test_cases_names
            ]

            selected_test_cases: list[FunctionType] = [
                test_case.function_type  # type: ignore[misc]
                for test_case in filtered_test_cases
                if (func and test_case.variant == TestCaseVariant.FUNCTIONAL)
                or (perf and test_case.variant == TestCaseVariant.PERFORMANCE)
            ]

            test_suites_with_cases.append(
                TestSuiteWithCases(
                    test_suite_class=test_suite_class,
                    test_cases=selected_test_cases,
                    config=test_suite_config,
                )
            )
        return test_suites_with_cases

    def _connect_nodes_and_run_test_run(
        self,
        sut_nodes: dict[str, SutNode],
        tg_nodes: dict[str, TGNode],
        sut_node_config: SutNodeConfiguration,
        tg_node_config: TGNodeConfiguration,
        test_run_config: TestRunConfiguration,
        test_run_result: TestRunResult,
        test_suites_with_cases: Iterable[TestSuiteWithCases],
    ) -> None:
        """Connect nodes, then continue to run the given test run.

        Connect the :class:`SutNode` and the :class:`TGNode` of this `test_run_config`.
        If either has already been connected, it's going to be in either `sut_nodes` or `tg_nodes`,
        respectively.
        If not, connect and add the node to the respective `sut_nodes` or `tg_nodes` :class:`dict`.

        Args:
            sut_nodes: A dictionary storing connected/to be connected SUT nodes.
            tg_nodes: A dictionary storing connected/to be connected TG nodes.
            sut_node_config: The test run's SUT node configuration.
            tg_node_config: The test run's TG node configuration.
            test_run_config: A test run configuration.
            test_run_result: The test run's result.
            test_suites_with_cases: The test suites with test cases to run.
        """
        sut_node = sut_nodes.get(sut_node_config.name)
        tg_node = tg_nodes.get(tg_node_config.name)

        try:
            if not sut_node:
                sut_node = SutNode(sut_node_config)
                sut_nodes[sut_node.name] = sut_node
            if not tg_node:
                tg_node = TGNode(tg_node_config)
                tg_nodes[tg_node.name] = tg_node
        except Exception as e:
            failed_node = test_run_config.system_under_test_node.node_name
            if sut_node:
                failed_node = test_run_config.traffic_generator_node
            self._logger.exception(f"The Creation of node {failed_node} failed.")
            test_run_result.update_setup(Result.FAIL, e)

        else:
            self._run_test_run(
                sut_node, tg_node, test_run_config, test_run_result, test_suites_with_cases
            )

    def _run_test_run(
        self,
        sut_node: SutNode,
        tg_node: TGNode,
        test_run_config: TestRunConfiguration,
        test_run_result: TestRunResult,
        test_suites_with_cases: Iterable[TestSuiteWithCases],
    ) -> None:
        """Run the given test run.

        This involves running the test run setup as well as running all build targets
        in the given test run. After that, the test run teardown is run.

        Args:
            sut_node: The test run's SUT node.
            tg_node: The test run's TG node.
            test_run_config: A test run configuration.
            test_run_result: The test run's result.
            test_suites_with_cases: The test suites with test cases to run.
        """
        self._logger.info(
            f"Running test run with SUT '{test_run_config.system_under_test_node.node_name}'."
        )
        test_run_result.add_sut_info(sut_node.node_info)
        try:
            sut_node.set_up_test_run(test_run_config)
            tg_node.set_up_test_run(test_run_config)
            test_run_result.update_setup(Result.PASS)
        except Exception as e:
            self._logger.exception("Test run setup failed.")
            test_run_result.update_setup(Result.FAIL, e)

        else:
            for build_target_config in test_run_config.build_targets:
                build_target_result = test_run_result.add_build_target(build_target_config)
                self._run_build_target(
                    sut_node,
                    tg_node,
                    build_target_config,
                    build_target_result,
                    test_suites_with_cases,
                )

        finally:
            try:
                self._logger.set_stage(DtsStage.test_run_teardown)
                sut_node.tear_down_test_run()
                tg_node.tear_down_test_run()
                test_run_result.update_teardown(Result.PASS)
            except Exception as e:
                self._logger.exception("Test run teardown failed.")
                test_run_result.update_teardown(Result.FAIL, e)

    def _run_build_target(
        self,
        sut_node: SutNode,
        tg_node: TGNode,
        build_target_config: BuildTargetConfiguration,
        build_target_result: BuildTargetResult,
        test_suites_with_cases: Iterable[TestSuiteWithCases],
    ) -> None:
        """Run the given build target.

        This involves running the build target setup as well as running all test suites
        of the build target's test run.
        After that, build target teardown is run.

        Args:
            sut_node: The test run's sut node.
            tg_node: The test run's tg node.
            build_target_config: A build target's test run configuration.
            build_target_result: The build target level result object associated
                with the current build target.
            test_suites_with_cases: The test suites with test cases to run.
        """
        self._logger.set_stage(DtsStage.build_target_setup)
        self._logger.info(f"Running build target '{build_target_config.name}'.")

        try:
            sut_node.set_up_build_target(build_target_config)
            self._result.dpdk_version = sut_node.dpdk_version
            build_target_result.add_build_target_info(sut_node.get_build_target_info())
            build_target_result.update_setup(Result.PASS)
        except Exception as e:
            self._logger.exception("Build target setup failed.")
            build_target_result.update_setup(Result.FAIL, e)

        else:
            self._run_test_suites(sut_node, tg_node, build_target_result, test_suites_with_cases)

        finally:
            try:
                self._logger.set_stage(DtsStage.build_target_teardown)
                sut_node.tear_down_build_target()
                build_target_result.update_teardown(Result.PASS)
            except Exception as e:
                self._logger.exception("Build target teardown failed.")
                build_target_result.update_teardown(Result.FAIL, e)

    def _run_test_suites(
        self,
        sut_node: SutNode,
        tg_node: TGNode,
        build_target_result: BuildTargetResult,
        test_suites_with_cases: Iterable[TestSuiteWithCases],
    ) -> None:
        """Run `test_suites_with_cases` with the current build target.

        The method assumes the build target we're testing has already been built on the SUT node.
        The current build target thus corresponds to the current DPDK build present on the SUT node.

        If a blocking test suite (such as the smoke test suite) fails, the rest of the test suites
        in the current build target won't be executed.

        Args:
            sut_node: The test run's SUT node.
            tg_node: The test run's TG node.
            build_target_result: The build target level result object associated
                with the current build target.
            test_suites_with_cases: The test suites with test cases to run.
        """
        end_build_target = False
        for test_suite_with_cases in test_suites_with_cases:
            test_suite_result = build_target_result.add_test_suite(test_suite_with_cases)
            try:
                self._run_test_suite(sut_node, tg_node, test_suite_result, test_suite_with_cases)
            except BlockingTestSuiteError as e:
                self._logger.exception(
                    f"An error occurred within {test_suite_with_cases.test_suite_class.__name__}. "
                    "Skipping build target..."
                )
                self._result.add_error(e)
                end_build_target = True
            # if a blocking test failed and we need to bail out of suite executions
            if end_build_target:
                break

    def _run_test_suite(
        self,
        sut_node: SutNode,
        tg_node: TGNode,
        test_suite_result: TestSuiteResult,
        test_suite_with_cases: TestSuiteWithCases,
    ) -> None:
        """Set up, execute and tear down `test_suite_with_cases`.

        The method assumes the build target we're testing has already been built on the SUT node.
        The current build target thus corresponds to the current DPDK build present on the SUT node.

        Test suite execution consists of running the discovered test cases.
        A test case run consists of setup, execution and teardown of said test case.

        Record the setup and the teardown and handle failures.

        Args:
            sut_node: The test run's SUT node.
            tg_node: The test run's TG node.
            test_suite_result: The test suite level result object associated
                with the current test suite.
            test_suite_with_cases: The test suite with test cases to run.

        Raises:
            BlockingTestSuiteError: If a blocking test suite fails.
        """
        test_suite_name = test_suite_with_cases.test_suite_class.__name__
        self._logger.set_stage(
            DtsStage.test_suite_setup, Path(SETTINGS.output_dir, test_suite_name)
        )
        test_suite = test_suite_with_cases.test_suite_class(
            sut_node, tg_node, test_suite_with_cases.config
        )
        try:
            self._logger.info(f"Starting test suite setup: {test_suite_name}")
            test_suite.set_up_suite()
            test_suite_result.update_setup(Result.PASS)
            self._logger.info(f"Test suite setup successful: {test_suite_name}")
        except Exception as e:
            self._logger.exception(f"Test suite setup ERROR: {test_suite_name}")
            test_suite_result.update_setup(Result.ERROR, e)

        else:
            self._execute_test_suite(
                test_suite,
                test_suite_with_cases.test_cases,
                test_suite_result,
            )
        finally:
            try:
                self._logger.set_stage(DtsStage.test_suite_teardown)
                test_suite.tear_down_suite()
                sut_node.kill_cleanup_dpdk_apps()
                test_suite_result.update_teardown(Result.PASS)
            except Exception as e:
                self._logger.exception(f"Test suite teardown ERROR: {test_suite_name}")
                self._logger.warning(
                    f"Test suite '{test_suite_name}' teardown failed, "
                    "the next test suite may be affected."
                )
                test_suite_result.update_setup(Result.ERROR, e)
            if len(test_suite_result.get_errors()) > 0 and test_suite.is_blocking:
                raise BlockingTestSuiteError(test_suite_name)

    def _execute_test_suite(
        self,
        test_suite: TestSuite,
        test_cases: Iterable[FunctionType],
        test_suite_result: TestSuiteResult,
    ) -> None:
        """Execute all `test_cases` in `test_suite`.

        If the :option:`--re-run` command line argument or the :envvar:`DTS_RERUN` environment
        variable is set, in case of a test case failure, the test case will be executed again
        until it passes or it fails that many times in addition of the first failure.

        Args:
            test_suite: The test suite object.
            test_cases: The list of test case methods.
            test_suite_result: The test suite level result object associated
                with the current test suite.
        """
        self._logger.set_stage(DtsStage.test_suite)
        for test_case_method in test_cases:
            test_case_name = test_case_method.__name__
            test_case_result = test_suite_result.add_test_case(test_case_name)
            all_attempts = SETTINGS.re_run + 1
            attempt_nr = 1
            self._run_test_case(test_suite, test_case_method, test_case_result)
            while not test_case_result and attempt_nr < all_attempts:
                attempt_nr += 1
                self._logger.info(
                    f"Re-running FAILED test case '{test_case_name}'. "
                    f"Attempt number {attempt_nr} out of {all_attempts}."
                )
                self._run_test_case(test_suite, test_case_method, test_case_result)

    def _run_test_case(
        self,
        test_suite: TestSuite,
        test_case_method: FunctionType,
        test_case_result: TestCaseResult,
    ) -> None:
        """Setup, execute and teardown `test_case_method` from `test_suite`.

        Record the result of the setup and the teardown and handle failures.

        Args:
            test_suite: The test suite object.
            test_case_method: The test case method.
            test_case_result: The test case level result object associated
                with the current test case.
        """
        test_case_name = test_case_method.__name__

        try:
            # run set_up function for each case
            test_suite.set_up_test_case()
            test_case_result.update_setup(Result.PASS)
        except SSHTimeoutError as e:
            self._logger.exception(f"Test case setup FAILED: {test_case_name}")
            test_case_result.update_setup(Result.FAIL, e)
        except Exception as e:
            self._logger.exception(f"Test case setup ERROR: {test_case_name}")
            test_case_result.update_setup(Result.ERROR, e)

        else:
            # run test case if setup was successful
            self._execute_test_case(test_suite, test_case_method, test_case_result)

        finally:
            try:
                test_suite.tear_down_test_case()
                test_case_result.update_teardown(Result.PASS)
            except Exception as e:
                self._logger.exception(f"Test case teardown ERROR: {test_case_name}")
                self._logger.warning(
                    f"Test case '{test_case_name}' teardown failed, "
                    f"the next test case may be affected."
                )
                test_case_result.update_teardown(Result.ERROR, e)
                test_case_result.update(Result.ERROR)

    def _execute_test_case(
        self,
        test_suite: TestSuite,
        test_case_method: FunctionType,
        test_case_result: TestCaseResult,
    ) -> None:
        """Execute `test_case_method` from `test_suite`, record the result and handle failures.

        Args:
            test_suite: The test suite object.
            test_case_method: The test case method.
            test_case_result: The test case level result object associated
                with the current test case.
        """
        test_case_name = test_case_method.__name__
        try:
            self._logger.info(f"Starting test case execution: {test_case_name}")
            test_case_method(test_suite)
            test_case_result.update(Result.PASS)
            self._logger.info(f"Test case execution PASSED: {test_case_name}")

        except TestCaseVerifyError as e:
            self._logger.exception(f"Test case execution FAILED: {test_case_name}")
            test_case_result.update(Result.FAIL, e)
        except Exception as e:
            self._logger.exception(f"Test case execution ERROR: {test_case_name}")
            test_case_result.update(Result.ERROR, e)
        except KeyboardInterrupt:
            self._logger.error(f"Test case execution INTERRUPTED by user: {test_case_name}")
            test_case_result.update(Result.SKIP)
            raise KeyboardInterrupt("Stop DTS")

    def _exit_dts(self) -> None:
        """Process all errors and exit with the proper exit code."""
        self._result.process()

        if self._logger:
            self._logger.info("DTS execution has ended.")

        sys.exit(self._result.get_return_code())
