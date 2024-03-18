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
    ARGS: The module level variable storing the state of the DTS arguments.
    SETTINGS: The module level variable storing framework-wide DTS settings.

Typical usage example::

  from framework.settings import SETTINGS
  foo = SETTINGS.foo
"""

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator, NamedTuple

from .config import TestSuiteConfig
from .utils import DPDKGitTarball


#: The prefix to be added to all of the environment variables.
ENV_PREFIX = "DTS_"


DPDK_TARBALL_PATH_ARGUMENT_NAME = "dpdk_tarball_path"
CONFIG_FILE_ARGUMENT_NAME = "config_file"
OUTPUT_DIR_ARGUMENT_NAME = "output_dir"
TIMEOUT_ARGUMENT_NAME = "timeout"
VERBOSE_ARGUMENT_NAME = "verbose"
SKIP_SETUP_ARGUMENT_NAME = "skip_setup"
COMPILE_TIMEOUT_ARGUMENT_NAME = "compile_timeout"
TEST_SUITES_ARGUMENT_NAME = "test_suites"
RERUN_ARGUMENT_NAME = "re_run"


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


class ArgumentEnvPair(NamedTuple):
    """A named tuple pairing the argument identifiers with its environment variable."""

    #: The argument name.
    arg_name: str

    #: The argument's associated environment variable name.
    env_var_name: str

    #: The argument's associated :class:`argparse.Action` name.
    action_name: str | None


@dataclass
class Argument:
    """A class representing a DTS argument."""

    #: The identifying name of the argument.
    #: It also translates into the corresponding :class:`Settings` attribute.
    name: str

    #: A list of flags to pass to :meth:`argparse.ArgumentParser.add_argument`.
    flags: tuple[str, ...]

    #: Any other keyword arguments to pass to :meth:`argparse.ArgumentParser.add_argument`.
    kwargs: dict[str, Any]

    #: The corresponding environment variable name.
    #: It is prefixed with the value stored in `ENV_PREFIX`.
    #: If not specified, it is automatically generated from the :attr:`~name`.
    env_var_name: str

    _from_env: bool = False

    #: A reference to its corresponding :class:`argparse.Action`.
    _action: argparse.Action | None = None

    def __init__(self, name: str, *flags: str, env_var_name: str | None = None, **kwargs: Any):
        """Class constructor.

        If the `help` argument is passed, this is prefixed with the
        argument's corresponding environment variable in square brackets."""

        self.name = name
        self.flags = flags
        self.kwargs = kwargs
        self.env_var_name = self._make_env_var(env_var_name)

        if "help" in self.kwargs:
            self.kwargs["help"] = f"[{self.env_var_name}] {self.kwargs['help']}"

    def add_to(self, parser: argparse._ActionsContainer):
        """Adds this argument to an :class:`argparse.ArgumentParser` instance."""
        self._action = parser.add_argument(*self.flags, dest=self.name, **self.kwargs)

    def _make_env_var(self, env_var_name: str | None) -> str:
        """Make the environment variable name."""
        return f"{ENV_PREFIX}{env_var_name or self.name.upper()}"

    def get_env_var(self) -> str | None:
        """Get environment variable if it was supplied instead of a command line flag."""

        env_var_value = os.environ.get(self.env_var_name)

        if env_var_value:
            # check if the user has supplied any of this argument's flags in the command line
            for flag in self.flags:
                if flag in sys.argv:
                    return None

        return env_var_value

    @property
    def from_env(self) -> bool:
        """Indicates if the argument value originated from the environment."""
        return self._from_env

    def inject_env_var(self, env_value: str) -> ArgumentEnvPair:
        """Injects the environment variable as a program argument.

        Injects this argument's flag with the supplied environment variable's value and
        returns an :class:`ArgumentEnvPair` object pairing this argument to its environment
        variable and :class:`argparse.Action`.

        The help notice of the argument is updated to display that the environment variable
        has been correctly picked up by showing its recorded value.

        .. note:: This method **must** be called after the argument has been added to the parser.
        """

        assert self._action is not None

        sys.argv[1:0] = [self.flags[0], env_value]

        self._from_env = True

        if "help" in self.kwargs:
            self.kwargs["help"] = f"{self.kwargs['help']} (env value: {env_value})"
        else:
            self.kwargs["help"] = f"(env value: {env_value})"

        self._action.help = self.kwargs["help"]

        return ArgumentEnvPair(
            arg_name=self.name,
            env_var_name=self.env_var_name,
            action_name=argparse._get_action_name(self._action),
        )


@dataclass
class ArgumentGroup:
    """A class grouping all the instances of :class:`Argument`.

    This class provides indexing to access an :class:`Argument` by name:

    >>> args["dpdk_revision_id"].env_var_name
    DTS_DPDK_REVISION_ID

    And can be iterated to access all the arguments:

    >>> arg_env_vars = [arg.env_var_name for arg in args]
    ['DPDK_TARBALL', ..]
    """

    #: The arguments values as parsed by :class:`argparse.ArgumentParse`.
    values: argparse.Namespace

    #: A dictionary pairing argument names to :class:`Argument` instances.
    _args: dict[str, Argument]

    #: A list of :class:`ArgumentEnvPair` containing all the successfully injected environment variables.
    _env_vars: list[ArgumentEnvPair]

    def __init__(self, *args: Argument):
        self._args = {arg.name: arg for arg in args}
        self._env_vars = []

    def __getitem__(self, arg_name: str) -> Argument:
        return self._args.__getitem__(arg_name)

    def __iter__(self) -> Generator[Argument, None, None]:
        yield from self._args.values()

    def add_environment_fed_argument(self, env_pair: ArgumentEnvPair):
        """Add an injected environment variable."""
        self._env_vars.append(env_pair)

    @property
    def environment_fed_arguments(self) -> list[ArgumentEnvPair]:
        """Returns the list of all the successfully injected environment variables."""
        return self._env_vars


ARGS = ArgumentGroup(
    Argument(
        CONFIG_FILE_ARGUMENT_NAME,
        "--config-file",
        default=SETTINGS.config_file_path,
        type=Path,
        help="The configuration file that describes the test cases, SUTs and targets.",
        metavar="FILE_PATH",
        env_var_name="CFG_FILE",
    ),
    Argument(
        OUTPUT_DIR_ARGUMENT_NAME,
        "--output-dir",
        "--output",
        default=SETTINGS.output_dir,
        help="Output directory where DTS logs and results are saved.",
        metavar="DIR_PATH",
    ),
    Argument(
        TIMEOUT_ARGUMENT_NAME,
        "-t",
        "--timeout",
        default=SETTINGS.timeout,
        type=float,
        help="The default timeout for all DTS operations except for compiling DPDK.",
        metavar="SECONDS",
    ),
    Argument(
        VERBOSE_ARGUMENT_NAME,
        "-v",
        "--verbose",
        action="store_true",
        help="Specify to enable verbose output, logging all messages " "to the console.",
    ),
    Argument(
        SKIP_SETUP_ARGUMENT_NAME,
        "-s",
        "--skip-setup",
        action="store_true",
        help="Specify to skip all setup steps on SUT and TG nodes.",
    ),
    Argument(
        DPDK_TARBALL_PATH_ARGUMENT_NAME,
        "--tarball",
        "--snapshot",
        "--git-ref",
        type=Path,
        default=SETTINGS.dpdk_tarball_path,
        help="Path to DPDK source code tarball or a git commit ID,"
        "tag ID or tree ID to test. To test local changes, first commit them, "
        "then use the commit ID with this option.",
        metavar="FILE_PATH",
        env_var_name="DPDK_TARBALL",
    ),
    Argument(
        COMPILE_TIMEOUT_ARGUMENT_NAME,
        "--compile-timeout",
        default=SETTINGS.compile_timeout,
        type=float,
        help="The timeout for compiling DPDK.",
        metavar="SECONDS",
    ),
    Argument(
        TEST_SUITES_ARGUMENT_NAME,
        "--test-suite",
        action="append",
        nargs="+",
        default=SETTINGS.test_suites,
        help="A list containing a test suite with test cases. "
        "The first parameter is the test suite name, and the rest are test case names, "
        "which are optional. May be specified multiple times. To specify multiple test suites in "
        "the environment variable, join the lists with a comma. "
        "Examples: "
        "--test-suite SUITE1 CASE1 CASE2 --test-suite SUITE2 CASE1 ... | "
        "DTS_TEST_SUITES='SUITE1 CASE1 CASE2, SUITE2 CASE1, ...' | "
        "--test-suite SUITE1 --test-suite SUITE2 CASE1 ... | "
        "DTS_TEST_SUITES='SUITE1, SUITE2 CASE1, ...'",
        metavar=("TEST_SUITE", "TEST_CASES"),
    ),
    Argument(
        RERUN_ARGUMENT_NAME,
        "--re-run",
        "--re_run",
        default=SETTINGS.re_run,
        type=int,
        help="Re-run each test case the specified number of times if a test failure occurs.",
        env_var_name="RERUN",
        metavar="N_TIMES",
    ),
)


class ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with a custom error message.

    This custom version of ArgumentParser changes the error message to
    accurately reflect its origin if an environment variable is used
    as an argument.

    Instead of printing usage on every error, it prints instructions
    on how to do it.
    """

    def error(self, message):
        for _, env_var_name, action_name in ARGS.environment_fed_arguments:
            message = message.replace(
                f"argument {action_name}", f"environment variable {env_var_name}"
            )

        print(f"{self.prog}: error: {message}\n", file=sys.stderr)
        self.exit(2, "For help and usage, " "run the command with the --help flag.\n")


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
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    for arg in ARGS:
        arg.add_to(parser)

    return parser


def _process_test_suites(args: list[list[str]]) -> list[TestSuiteConfig]:
    """Process the given argument to a list of :class:`TestSuiteConfig` to execute.

    Args:
        args: The arguments to process. The args is a string from an environment variable
              or a list of from the user input containing tests suites with tests cases,
              each of which is a list of [test_suite, test_case, test_case, ...].

    Returns:
        A list of test suite configurations to execute.
    """
    if ARGS[TEST_SUITES_ARGUMENT_NAME].from_env:
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

    for arg in ARGS:
        env_value = arg.get_env_var()
        if env_value:
            env_pair = arg.inject_env_var(env_value)
            ARGS.add_environment_fed_argument(env_pair)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    ARGS.values = parser.parse_args()

    ARGS.values.dpdk_tarball_path = Path(
        Path(DPDKGitTarball(ARGS.values.dpdk_tarball_path, ARGS.values.output_dir))
        if not os.path.exists(ARGS.values.dpdk_tarball_path)
        else Path(ARGS.values.dpdk_tarball_path)
    )

    ARGS.values.test_suites = _process_test_suites(ARGS.values.test_suites)

    kwargs = {k: v for k, v in vars(ARGS.values).items() if hasattr(SETTINGS, k)}
    return Settings(**kwargs)
