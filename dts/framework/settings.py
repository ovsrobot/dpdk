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

.. option:: --dpdk-tree
.. envvar:: DTS_DPDK_TREE

    Path to DPDK source code tree to test.

.. option:: --tarball, --snapshot
.. envvar:: DTS_DPDK_TARBALL

    Path to DPDK source code tarball to test.

.. option:: --remote-source
.. envvar:: DTS_REMOTE_SOURCE

    Set when the DPDK source tree or tarball is located on the SUT node.

.. option:: --build-dir
.. envvar:: DTS_BUILD_DIR

    A directory name, which would be located in the `dpdk tree` or `tarball`.

.. option:: -f, --force
.. envvar:: DTS_FORCE

    Specify to remove an already existing DPDK tarball or tree before copying/extracting a new one.

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
from argparse import Action, ArgumentDefaultsHelpFormatter, _get_action_name
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import DPDKLocation, TestSuiteConfig


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
    dpdk_location: DPDKLocation | None = None
    #:
    force: bool = False
    #:
    compile_timeout: float = 1200
    #:
    test_suites: list[TestSuiteConfig] = field(default_factory=list)
    #:
    re_run: int = 0


SETTINGS: Settings = Settings()


#: Attribute name representing the env variable name to augment :class:`~argparse.Action` with.
_ENV_VAR_NAME_ATTR = "env_var_name"
#: Attribute name representing the value origin to augment :class:`~argparse.Action` with.
_IS_FROM_ENV_ATTR = "is_from_env"

#: The prefix to be added to all of the environment variables.
_ENV_PREFIX = "DTS_"


def _make_env_var_name(action: Action, env_var_name: str | None) -> str:
    """Make and assign an environment variable name to the given action."""
    env_var_name = f"{_ENV_PREFIX}{env_var_name or action.dest.upper()}"
    setattr(action, _ENV_VAR_NAME_ATTR, env_var_name)
    return env_var_name


def _get_env_var_name(action: Action) -> str | None:
    """Get the environment variable name of the given action."""
    return getattr(action, _ENV_VAR_NAME_ATTR, None)


def _set_is_from_env(action: Action) -> None:
    """Make the environment the given action's value origin."""
    setattr(action, _IS_FROM_ENV_ATTR, True)


def _is_from_env(action: Action) -> bool:
    """Check if the given action's value originated from the environment."""
    return getattr(action, _IS_FROM_ENV_ATTR, False)


def _is_action_in_args(action: Action) -> bool:
    """Check if the action is invoked in the command line arguments."""
    for option in action.option_strings:
        if option in sys.argv:
            return True
    return False


def _add_env_var_to_action(
    action: Action,
    env_var_name: str | None = None,
) -> None:
    """Add an argument with an environment variable to the parser."""
    env_var_name = _make_env_var_name(action, env_var_name)

    if not _is_action_in_args(action):
        env_var_value = os.environ.get(env_var_name)
        if env_var_value is not None:
            _set_is_from_env(action)
            sys.argv[1:0] = [action.format_usage(), env_var_value]


class _DTSArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with a custom error message.

    This custom version of ArgumentParser changes the error message to accurately reflect the origin
    of the value of its arguments. If it was supplied through the command line nothing changes, but
    if it was supplied as an environment variable this is correctly communicated.
    """

    def find_action(
        self, action_dest: str, filter_fn: Callable[[Action], bool] | None = None
    ) -> Action | None:
        """Find and return an action by its destination variable name.

        Arguments:
            action_dest: the destination variable name of the action to find.
            filter_fn: if an action is found it is passed to this filter function, which must
                return a boolean value.
        """
        it = (action for action in self._actions if action.dest == action_dest)
        action = next(it, None)

        if action and filter_fn:
            return action if filter_fn(action) else None

        return action

    def error(self, message):
        """Augments :meth:`~argparse.ArgumentParser.error` with environment variable awareness."""
        for action in self._actions:
            if _is_from_env(action):
                action_name = _get_action_name(action)
                env_var_name = _get_env_var_name(action)
                env_var_value = os.environ.get(env_var_name)

                message = message.replace(
                    f"argument {action_name}",
                    f"environment variable {env_var_name} (value: {env_var_value})",
                )

        print(f"{self.prog}: error: {message}\n", file=sys.stderr)
        self.exit(2, "For help and usage, " "run the command with the --help flag.\n")


class _EnvVarHelpFormatter(ArgumentDefaultsHelpFormatter):
    """Custom formatter to add environment variables to the help page."""

    def _get_help_string(self, action):
        """Overrides :meth:`ArgumentDefaultsHelpFormatter._get_help_string`."""
        help = super()._get_help_string(action)

        env_var_name = _get_env_var_name(action)
        if env_var_name is not None:
            help = f"[{env_var_name}] {help}"

            env_var_value = os.environ.get(env_var_name)
            if env_var_value is not None:
                help = f"{help} (env value: {env_var_value})"

        return help


def _required_with_one_of(parser: _DTSArgumentParser, action: Action, *required_dests: str) -> None:
    """Verify that `action` is listed together with `required_dests`.

    Verify that a specific action is included in the command-line arguments or environment variables
    if at least one of the required destination is already defined in the command-line arguments or
    environment variables.

    Args:
        parser: The custom ArgumentParser object which contains `action`.
        action: The action to be verified.
        *required_dests: Destination variable names of the required arguments.

    Raises:
        argparse.ArgumentTypeError: If the action is not included when one
            of the required arguments is present.

    Example:
        For etc. if the `--option1` argument is provided, then the `--option2` argument
        must also be included too. Only one of the required_dests needs to be provided for
        the check to be applied.

        parser = _DTSArgumentParser()
        option1_arg = parser.add_argument('--option1', dest='option1', action='store_true')
        option2_arg = arser.add_argument('--option2', dest='option2', action='store_true')

        _required_with_one_of(parser, option1_arg, 'option2')

    """
    if _is_action_in_args(action):
        for required_dest in required_dests:
            required_action = parser.find_action(required_dest)
            if required_action is None:
                continue

            if _is_action_in_args(required_action):
                return None

        raise argparse.ArgumentTypeError(
            f"The '{action.dest}' is required at least with one of '{', '.join(required_dests)}'."
        )


def _get_parser() -> _DTSArgumentParser:
    """Create the argument parser for DTS.

    Command line options take precedence over environment variables, which in turn take precedence
    over default values.

    Returns:
        _DTSArgumentParser: The configured argument parser with defined options.
    """
    parser = _DTSArgumentParser(
        description="Run DPDK test suites. All options may be specified with the environment "
        "variables provided in brackets. Command line arguments have higher priority.",
        formatter_class=_EnvVarHelpFormatter,
        allow_abbrev=False,
    )

    action = parser.add_argument(
        "--config-file",
        default=SETTINGS.config_file_path,
        type=Path,
        help="The configuration file that describes the test cases, SUTs and DPDK build configs.",
        metavar="FILE_PATH",
        dest="config_file_path",
    )
    _add_env_var_to_action(action, "CFG_FILE")

    action = parser.add_argument(
        "--output-dir",
        "--output",
        default=SETTINGS.output_dir,
        help="Output directory where DTS logs and results are saved.",
        metavar="DIR_PATH",
    )
    _add_env_var_to_action(action)

    action = parser.add_argument(
        "-t",
        "--timeout",
        default=SETTINGS.timeout,
        type=float,
        help="The default timeout for all DTS operations except for compiling DPDK.",
        metavar="SECONDS",
    )
    _add_env_var_to_action(action)

    action = parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=SETTINGS.verbose,
        help="Specify to enable verbose output, logging all messages to the console.",
    )
    _add_env_var_to_action(action)

    dpdk_source = parser.add_mutually_exclusive_group()

    action = dpdk_source.add_argument(
        "--dpdk-tree",
        help="Path to DPDK source code tree to test.",
        metavar="DIR_PATH",
        dest="dpdk_tree_path",
    )
    _add_env_var_to_action(action, "DPDK_TREE")

    action = dpdk_source.add_argument(
        "--tarball",
        "--snapshot",
        help="Path to DPDK source code tarball to test.",
        metavar="FILE_PATH",
        dest="dpdk_tarball_path",
    )
    _add_env_var_to_action(action, "DPDK_TARBALL")

    action = parser.add_argument(
        "--remote-source",
        action="store_true",
        default=False,
        help="Set when the DPDK source tree or tarball is located on the SUT node.",
    )
    _add_env_var_to_action(action)
    _required_with_one_of(parser, action, "dpdk_tarball_path", "dpdk_tree_path")

    action = parser.add_argument(
        "--build-dir",
        help="A directory name, which would be located in the `dpdk tree` or `tarball`.",
        metavar="DIR_NAME",
    )
    _add_env_var_to_action(action)
    _required_with_one_of(parser, action, "dpdk_tarball_path", "dpdk_tree_path")

    action = parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=SETTINGS.force,
        help="Specify to remove an already existing dpdk tarball before copying/extracting a "
        "new one.",
    )
    _add_env_var_to_action(action)

    action = parser.add_argument(
        "--compile-timeout",
        default=SETTINGS.compile_timeout,
        type=float,
        help="The timeout for compiling DPDK.",
        metavar="SECONDS",
    )
    _add_env_var_to_action(action)

    action = parser.add_argument(
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
    _add_env_var_to_action(action)

    action = parser.add_argument(
        "--re-run",
        "--re_run",
        default=SETTINGS.re_run,
        type=int,
        help="Re-run each test case the specified number of times if a test failure occurs.",
        metavar="N_TIMES",
    )
    _add_env_var_to_action(action, "RERUN")

    return parser


def _process_dpdk_location(
    dpdk_tree: str | None,
    tarball: str | None,
    remote: bool,
    build_dir: str | None,
):
    """Process and validate DPDK build arguments.

    Ensures that either `dpdk_tree` or `tarball` is provided and, if local
    (`remote` is False), verifies their existence. Constructs and returns
    a `DPDKLocation` object with the provided parameters if validation is
    successful, or `None` if neither `dpdk_tree` nor `tarball` is given.

    Args:
        dpdk_tree: The path to the DPDK tree.
        tarball: The path to the DPDK tarball.
        remote: If :data:`True`, `dpdk_tree` or `tarball` is on the SUT node.
        build_dir: A directory name, which would be located in the `dpdk tree` or `tarball`.

    Returns:
        A DPDK location if construction is successful, otherwise None.

    Raises:
        argparse.ArgumentTypeError: If `dpdk_tree` or `tarball` not found in local filesystem.
    """
    if dpdk_tree or tarball:
        if not remote:
            if dpdk_tree and not Path(dpdk_tree).is_dir():
                raise argparse.ArgumentTypeError(
                    f"DPDK tree '{dpdk_tree}' not found in local filesystem."
                )
            if tarball and not Path(tarball).is_file():
                raise argparse.ArgumentTypeError(
                    f"DPDK tarball '{tarball}' not found in local filesystem."
                )

        return DPDKLocation(
            dpdk_tree=dpdk_tree, tarball=tarball, remote=remote, build_dir=build_dir
        )

    return None


def _process_test_suites(
    parser: _DTSArgumentParser, args: list[list[str]]
) -> list[TestSuiteConfig]:
    """Process the given argument to a list of :class:`TestSuiteConfig` to execute.

    Args:
        args: The arguments to process. The args is a string from an environment variable
              or a list of from the user input containing tests suites with tests cases,
              each of which is a list of [test_suite, test_case, test_case, ...].

    Returns:
        A list of test suite configurations to execute.
    """
    if parser.find_action("test_suites", _is_from_env):
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
    args = parser.parse_args()

    args.dpdk_location = _process_dpdk_location(
        args.dpdk_tree_path, args.dpdk_tarball_path, args.remote_source, args.build_dir
    )
    args.test_suites = _process_test_suites(parser, args.test_suites)

    kwargs = {k: v for k, v in vars(args).items() if hasattr(SETTINGS, k)}
    return Settings(**kwargs)
