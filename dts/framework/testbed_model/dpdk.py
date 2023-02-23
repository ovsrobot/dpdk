# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2023 PANTHEON.tech s.r.o.

"""
Various utilities used for configuring, building and running DPDK.
"""


class MesonArgs(object):
    """
    Aggregate the arguments needed to build DPDK:
    default_library: Default library type, Meson allows "shared", "static" and "both".
               Defaults to None, in which case the argument won't be used.
    Keyword arguments: The arguments found in meson_option.txt in root DPDK directory.
               Do not use -D with them, for example: enable_kmods=True.
    """

    default_library: str

    def __init__(self, default_library: str | None = None, **dpdk_args: str | bool):
        self.default_library = (
            f"--default-library={default_library}" if default_library else ""
        )
        self.dpdk_args = " ".join(
            (
                f"-D{dpdk_arg_name}={dpdk_arg_value}"
                for dpdk_arg_name, dpdk_arg_value in dpdk_args.items()
            )
        )

    def __str__(self) -> str:
        return " ".join(f"{self.default_library} {self.dpdk_args}".split())
