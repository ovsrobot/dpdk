# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import argparse
import os
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Sequence, TypeVar

_T = TypeVar("_T")


def _env_arg(env_var: str) -> Any:
    class _EnvironmentArgument(argparse.Action):
        def __init__(
            self,
            option_strings: Sequence[str],
            dest: str,
            nargs: Optional[str | int] = None,
            const: Optional[str] = None,
            default: str = None,
            type: Callable[[str], Optional[_T | argparse.FileType]] = None,
            choices: Optional[Iterable[_T]] = None,
            required: bool = True,
            help: Optional[str] = None,
            metavar: Optional[str | tuple[str, ...]] = None,
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
    verbose: bool


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
        "-v",
        "--verbose",
        action=_env_arg("DTS_VERBOSE"),
        default="N",
        required=False,
        help="[DTS_VERBOSE] Set to 'Y' to enable verbose output, logging all messages "
        "to the console.",
    )

    return parser


def _get_settings() -> _Settings:
    parsed_args = _get_parser().parse_args()
    return _Settings(
        config_file_path=parsed_args.config_file,
        output_dir=parsed_args.output_dir,
        verbose=(parsed_args.verbose == "Y"),
    )


SETTINGS: _Settings = _get_settings()
