# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2021 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import argparse
import os
from dataclasses import dataclass
from typing import Any


class _EnvironmentArgument(argparse.Action):
    def __init__(
        self, env_var: str, required: bool = True, default: Any = None, **kwargs
    ):
        env_var_value = os.environ.get(env_var)
        default = env_var_value or default
        super(_EnvironmentArgument, self).__init__(
            default=default, required=default is None and required, **kwargs
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str = None,
    ) -> None:
        setattr(namespace, self.dest, values)


def _env_arg(envvar: str) -> Any:
    def wrapper(**kwargs) -> _EnvironmentArgument:
        return _EnvironmentArgument(envvar, **kwargs)

    return wrapper


@dataclass(slots=True, frozen=True)
class _Settings:
    config_file_path: str
    timeout: float


def _get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DPDK test framework.")

    parser.add_argument(
        "--config-file",
        action=_env_arg("DTS_CFG_FILE"),
        default="conf.yaml",
        help="[DTS_CFG_FILE] configuration file that describes the test cases, SUTs and targets",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        action=_env_arg("DTS_TIMEOUT"),
        default=15,
        required=False,
        help="[DTS_TIMEOUT] The default timeout for all DTS operations except for compiling DPDK.",
    )

    return parser


def _get_settings() -> _Settings:
    args = _get_parser().parse_args()
    return _Settings(
        config_file_path=args.config_file,
        timeout=float(args.timeout),
    )


SETTINGS: _Settings = _get_settings()
