# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
# Copyright(c) 2022-2023 PANTHEON.tech s.r.o.
# Copyright(c) 2022-2023 University of New Hampshire

import argparse
import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from .exception import ConfigurationError

_T = TypeVar("_T")


def _env_arg(env_var: str) -> Any:
    class _EnvironmentArgument(argparse.Action):
        def __init__(
            self,
            option_strings: Sequence[str],
            dest: str,
            nargs: str | int | None = None,
            const: str | None = None,
            default: str = None,
            type: Callable[[str], _T | argparse.FileType | None] = None,
            choices: Iterable[_T] | None = None,
            required: bool = True,
            help: str | None = None,
            metavar: str | tuple[str, ...] | None = None,
        ) -> None:
            env_var_value = os.environ.get(env_var)
            default = env_var_value or default
            super(_EnvironmentArgument, self).__init__(
                option_strings,
                dest,
                nargs=nargs,
                const=const,
                default=default,
                type=type,
                choices=choices,
                required=required,
                help=help,
                metavar=metavar,
            )

        def __call__(
            self,
            parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            values: Any,
            option_string: str = None,
        ) -> None:
            setattr(namespace, self.dest, values)

    return _EnvironmentArgument


@dataclass(slots=True, frozen=True)
class _Settings:
    config_file_path: str
    output_dir: str
    timeout: float
    verbose: bool
    skip_setup: bool
    dpdk_ref: Path | str
    compile_timeout: float
    test_cases: list
    re_run: int


def _get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DPDK test framework.")

    parser.add_argument(
        "--config-file",
        action=_env_arg("DTS_CFG_FILE"),
        default="conf.yaml",
        required=False,
        help="[DTS_CFG_FILE] configuration file that describes the test cases, SUTs "
        "and targets.",
    )

    parser.add_argument(
        "--output-dir",
        "--output",
        action=_env_arg("DTS_OUTPUT_DIR"),
        default="output",
        required=False,
        help="[DTS_OUTPUT_DIR] Output directory where dts logs and results are saved.",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        action=_env_arg("DTS_TIMEOUT"),
        default=15,
        type=float,
        required=False,
        help="[DTS_TIMEOUT] The default timeout for all DTS operations except for "
        "compiling DPDK.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action=_env_arg("DTS_VERBOSE"),
        default="N",
        required=False,
        help="[DTS_VERBOSE] Set to 'Y' to enable verbose output, logging all messages "
        "to the console.",
    )

    parser.add_argument(
        "-s",
        "--skip-setup",
        action=_env_arg("DTS_SKIP_SETUP"),
        required=False,
        help="[DTS_SKIP_SETUP] Set to 'Y' to skip all setup steps on SUT and TG nodes.",
    )

    parser.add_argument(
        "--dpdk-ref",
        "--git",
        "--snapshot",
        action=_env_arg("DTS_DPDK_REF"),
        default="dpdk.tar.xz",
        required=False,
        help="[DTS_DPDK_REF] Reference to DPDK source code, "
        "can be either a path to a tarball or a git refspec. "
        "In case of a tarball, it will be extracted in the same directory.",
    )

    parser.add_argument(
        "--compile-timeout",
        action=_env_arg("DTS_COMPILE_TIMEOUT"),
        default=1200,
        type=float,
        required=False,
        help="[DTS_COMPILE_TIMEOUT] The timeout for compiling DPDK.",
    )

    parser.add_argument(
        "--test-cases",
        action=_env_arg("DTS_TESTCASES"),
        default="",
        required=False,
        help="[DTS_TESTCASES] Comma-separated list of test cases to execute. "
        "Unknown test cases will be silently ignored.",
    )

    parser.add_argument(
        "--re-run",
        "--re_run",
        action=_env_arg("DTS_RERUN"),
        default=0,
        type=int,
        required=False,
        help="[DTS_RERUN] Re-run each test case the specified amount of times "
        "if a test failure occurs",
    )

    return parser


def _check_dpdk_ref(parsed_args: argparse.Namespace) -> None:
    if not os.path.exists(parsed_args.dpdk_ref):
        raise ConfigurationError(
            f"DPDK tarball '{parsed_args.dpdk_ref}' doesn't exist."
        )
    else:
        parsed_args.dpdk_ref = Path(parsed_args.dpdk_ref)


def _get_settings() -> _Settings:
    parsed_args = _get_parser().parse_args()
    _check_dpdk_ref(parsed_args)
    return _Settings(
        config_file_path=parsed_args.config_file,
        output_dir=parsed_args.output_dir,
        timeout=parsed_args.timeout,
        verbose=(parsed_args.verbose == "Y"),
        skip_setup=(parsed_args.skip_setup == "Y"),
        dpdk_ref=parsed_args.dpdk_ref,
        compile_timeout=parsed_args.compile_timeout,
        test_cases=parsed_args.test_cases.split(",") if parsed_args.test_cases else [],
        re_run=parsed_args.re_run,
    )


SETTINGS: _Settings = _get_settings()
