# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
# Copyright(c) 2022-2023 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
# Copyright(c) 2024 Arm Limited

"""Environment variables and command line arguments parsing.

This is a simple module utilizing the built-in argparse module to parse command line arguments,
augment them with values from environment variables and make them available across the framework.

The command line value takes precedence, followed by the environment variable value,
followed by the default value defined in this module.

The command line arguments along with the supported environment variables are:

.. option:: --config-file
.. envvar:: DTS_CFG_FILE

    The path to the YAML test run configuration file.

.. option:: --output-dir, --output
.. envvar:: DTS_OUTPUT_DIR

    The directory where DTS logs and results are saved.

.. option:: --compile-timeout
.. envvar:: DTS_COMPILE_TIMEOUT

    The timeout for compiling DPDK.

.. option:: -t, --timeout
.. envvar:: DTS_TIMEOUT

    The timeout for all DTS operation except for compiling DPDK.

.. option:: -v, --verbose
.. envvar:: DTS_VERBOSE

    Set to any value to enable logging everything to the console.

.. option:: -s, --skip-setup
.. envvar:: DTS_SKIP_SETUP

    Set to any value to skip building DPDK.

.. option:: --tarball, --snapshot, --git-ref
.. envvar:: DTS_DPDK_TARBALL

    The path to a DPDK tarball, git commit ID, tag ID or tree ID to test.

.. option:: --test-suite
.. envvar:: DTS_TEST_SUITES

        A test suite with test cases which may be specified multiple times.
        In the environment variable, the suites are joined with a comma.

.. option:: --re-run, --re_run
.. envvar:: DTS_RERUN

    Re-run each test case this many times in case of a failure.

The module provides one key module-level variable:

Attributes:
    SETTINGS: The module level variable storing framework-wide DTS settings.

Typical usage example::

  from framework.settings import SETTINGS
  foo = SETTINGS.foo
"""

import argparse
import os
import sys
from argparse import (
    Action,
    ArgumentDefaultsHelpFormatter,
    _get_action_name,
)
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, ParamSpec

from .config import TestSuiteConfig
from .utils import DPDKGitTarball


@dataclass(slots=True)
class Settings:
    """Default framework-wide user settings.

    The defaults may be modified at the start of the run.
    """

    #:
    config_file_path: Path = Path(__file__).parent.parent.joinpath("conf.yaml")
    #:
    output_dir: str = "output"
    #:
    timeout: float = 15
    #:
    verbose: bool = False
    #:
    skip_setup: bool = False
    #:
    dpdk_tarball_path: Path | str = "dpdk.tar.xz"
    #:
    compile_timeout: float = 1200
    #:
    test_suites: list[TestSuiteConfig] = field(default_factory=list)
    #:
    re_run: int = 0


SETTINGS: Settings = Settings()

P = ParamSpec("P")

#: Attribute name representing the env variable name to augment :class:`~argparse.Action` with.
_ENV_VAR_NAME_ATTR = "env_var_name"
#: Attribute name representing the value origin to augment :class:`~argparse.Action` with.
_IS_FROM_ENV_ATTR = "is_from_env"

#: The prefix to be added to all of the environment variables.
ENV_PREFIX = "DTS_"


def is_action_in_args(action: Action) -> bool:
    """Check if the action is invoked in the command line arguments."""
    for option in action.option_strings:
        if option in sys.argv:
            return True
    return False


def make_env_var_name(action: Action, env_var_name: str | None) -> str:
    """Make and assign an environment variable name to the given action."""
    env_var_name = f"{ENV_PREFIX}{env_var_name or action.dest.upper()}"
    setattr(action, _ENV_VAR_NAME_ATTR, env_var_name)
    return env_var_name


def get_env_var_name(action: Action) -> str | None:
    """Get the environment variable name of the given action."""
    return getattr(action, _ENV_VAR_NAME_ATTR, None)


def set_is_from_env(action: Action) -> None:
    """Make the environment the given action's value origin."""
    setattr(action, _IS_FROM_ENV_ATTR, True)


def is_from_env(action: Action) -> bool:
    """Check if the given action's value originated from the environment."""
    return getattr(action, _IS_FROM_ENV_ATTR, False)


def augment_add_argument_with_env(
    add_argument_fn: Callable[P, Action],
):
    """Augment any :class:`~argparse._ActionsContainer.add_argument` with environment variables."""

    def _add_argument(
        *args: P.args,
        env_var_name: str | None = None,
        **kwargs: P.kwargs,
    ) -> Action:
        """Add an argument with an environment variable to the parser."""
        action = add_argument_fn(*args, **kwargs)
        env_var_name = make_env_var_name(action, env_var_name)

        if not is_action_in_args(action):
            env_var_value = os.environ.get(env_var_name)
            if env_var_value:
                set_is_from_env(action)
                sys.argv[1:0] = [action.format_usage(), env_var_value]

        return action

    return _add_argument


class ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with a custom error message.

    This custom version of ArgumentParser changes the error message to
    accurately reflect its origin if an environment variable is used
    as an argument.

    Instead of printing usage on every error, it prints instructions
    on how to do it.
    """

    def find_action(
        self, action_name: str, filter_fn: Callable[[Action], bool] | None = None
    ) -> Action | None:
        """Find and return an action by its name.

        Arguments:
            action_name: the name of the action to find.
            filter_fn: a filter function to use in the search.
        """
        it = (action for action in self._actions if action_name == _get_action_name(action))
        action = next(it, None)

        if action is not None and filter_fn is not None:
            return action if filter_fn(action) else None

        return action

    def error(self, message):
        """Augments :meth:`~argparse.ArgumentParser.error` with environment variable awareness."""
        for action in self._actions:
            if is_from_env(action):
                action_name = _get_action_name(action)
                env_var_name = get_env_var_name(action)
                env_var_value = os.environ.get(env_var_name)

                message = message.replace(
                    f"argument {action_name}",
                    f"environment variable {env_var_name} (value: {env_var_value})",
                )

        print(f"{self.prog}: error: {message}\n", file=sys.stderr)
        self.exit(2, "For help and usage, " "run the command with the --help flag.\n")


class EnvVarHelpFormatter(ArgumentDefaultsHelpFormatter):
    """Custom formatter to add environment variables in the help page."""

    def _get_help_string(self, action):
        """Overrides :meth:`ArgumentDefaultsHelpFormatter._get_help_string`."""
        help = super()._get_help_string(action)

        env_var_name = get_env_var_name(action)
        if env_var_name is not None:
            help = f"[{env_var_name}] {help}"

            env_var_value = os.environ.get(env_var_name)
            if env_var_value is not None:
                help += f" (env value: {env_var_value})"

        return help


def _get_parser() -> ArgumentParser:
    """Create the argument parser for DTS.

    Command line options take precedence over environment variables, which in turn take precedence
    over default values.

    Returns:
        ArgumentParser: The configured argument parser with defined options.
    """
    parser = ArgumentParser(
        description="Run DPDK test suites. All options may be specified with the environment "
        "variables provided in brackets. Command line arguments have higher priority.",
        formatter_class=EnvVarHelpFormatter,
        allow_abbrev=False,
    )

    add_argument_to_parser_with_env = augment_add_argument_with_env(parser.add_argument)

    add_argument_to_parser_with_env(
        "--config-file",
        default=SETTINGS.config_file_path,
        type=Path,
        help="The configuration file that describes the test cases, SUTs and targets.",
        metavar="FILE_PATH",
        env_var_name="CFG_FILE",
    )

    add_argument_to_parser_with_env(
        "--output-dir",
        "--output",
        default=SETTINGS.output_dir,
        help="Output directory where DTS logs and results are saved.",
        metavar="DIR_PATH",
    )

    add_argument_to_parser_with_env(
        "-t",
        "--timeout",
        default=SETTINGS.timeout,
        type=float,
        help="The default timeout for all DTS operations except for compiling DPDK.",
        metavar="SECONDS",
    )

    add_argument_to_parser_with_env(
        "-v",
        "--verbose",
        action="store_true",
        default=SETTINGS.verbose,
        help="Specify to enable verbose output, logging all messages to the console.",
    )

    add_argument_to_parser_with_env(
        "-s",
        "--skip-setup",
        action="store_true",
        default=SETTINGS.skip_setup,
        help="Specify to skip all setup steps on SUT and TG nodes.",
    )

    add_argument_to_parser_with_env(
        "--tarball",
        "--snapshot",
        "--git-ref",
        default=SETTINGS.dpdk_tarball_path,
        type=Path,
        help="Path to DPDK source code tarball or a git commit ID, "
        "tag ID or tree ID to test. To test local changes, first commit them, "
        "then use the commit ID with this option.",
        metavar="FILE_PATH",
        dest="dpdk_tarball_path",
        env_var_name="DPDK_TARBALL",
    )

    add_argument_to_parser_with_env(
        "--compile-timeout",
        default=SETTINGS.compile_timeout,
        type=float,
        help="The timeout for compiling DPDK.",
        metavar="SECONDS",
    )

    add_argument_to_parser_with_env(
        "--test-suite",
        action="append",
        nargs="+",
        metavar=("TEST_SUITE", "TEST_CASES"),
        default=SETTINGS.test_suites,
        help="A list containing a test suite with test cases. "
        "The first parameter is the test suite name, and the rest are test case names, "
        "which are optional. May be specified multiple times. To specify multiple test suites in "
        "the environment variable, join the lists with a comma. "
        "Examples: "
        "--test-suite suite case case --test-suite suite case ... | "
        "DTS_TEST_SUITES='suite case case, suite case, ...' | "
        "--test-suite suite --test-suite suite case ... | "
        "DTS_TEST_SUITES='suite, suite case, ...'",
        dest="test_suites",
    )

    add_argument_to_parser_with_env(
        "--re-run",
        "--re_run",
        default=SETTINGS.re_run,
        type=int,
        help="Re-run each test case the specified number of times if a test failure occurs.",
        env_var_name="RERUN",
        metavar="N_TIMES",
    )

    return parser


def _process_test_suites(parser: ArgumentParser, args: list[list[str]]) -> list[TestSuiteConfig]:
    """Process the given argument to a list of :class:`TestSuiteConfig` to execute.

    Args:
        args: The arguments to process. The args is a string from an environment variable
              or a list of from the user input containing tests suites with tests cases,
              each of which is a list of [test_suite, test_case, test_case, ...].

    Returns:
        A list of test suite configurations to execute.
    """
    test_suites = parser.find_action("test_suites", is_from_env)
    if test_suites is not None:
        # Environment variable in the form of "SUITE1 CASE1 CASE2, SUITE2 CASE1, SUITE3, ..."
        args = [suite_with_cases.split() for suite_with_cases in args[0][0].split(",")]

    return [TestSuiteConfig(test_suite, test_cases) for [test_suite, *test_cases] in args]


def get_settings() -> Settings:
    """Create new settings with inputs from the user.

    The inputs are taken from the command line and from environment variables.

    Returns:
        The new settings object.
    """
    parser = _get_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    args.dpdk_tarball_path = Path(
        Path(DPDKGitTarball(args.dpdk_tarball_path, args.output_dir))
        if not os.path.exists(args.dpdk_tarball_path)
        else Path(args.dpdk_tarball_path)
    )

    args.test_suites = _process_test_suites(parser, args.test_suites)

    kwargs = {k: v for k, v in vars(args).items() if hasattr(SETTINGS, k)}
    return Settings(**kwargs)
