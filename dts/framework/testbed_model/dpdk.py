# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2023 PANTHEON.tech s.r.o.

"""
Various utilities used for configuring, building and running DPDK.
"""

from .hw import LogicalCoreList, VirtualDevice


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


class EalParameters(object):
    def __init__(
        self,
        lcore_list: LogicalCoreList,
        memory_channels: int,
        prefix: str,
        no_pci: bool,
        vdevs: list[VirtualDevice],
        other_eal_param: str,
    ):
        """
        Generate eal parameters character string;
        :param lcore_list: the list of logical cores to use.
        :param memory_channels: the number of memory channels to use.
        :param prefix: set file prefix string, eg:
                        prefix='vf'
        :param no_pci: switch of disable PCI bus eg:
                        no_pci=True
        :param vdevs: virtual device list, eg:
                        vdevs=['net_ring0', 'net_ring1']
        :param other_eal_param: user defined DPDK eal parameters, eg:
                        other_eal_param='--single-file-segments'
        """
        self._lcore_list = f"-l {lcore_list}"
        self._memory_channels = f"-n {memory_channels}"
        self._prefix = prefix
        if prefix:
            self._prefix = f"--file-prefix={prefix}"
        self._no_pci = "--no-pci" if no_pci else ""
        self._vdevs = " ".join(f"--vdev {vdev}" for vdev in vdevs)
        self._other_eal_param = other_eal_param

    def __str__(self) -> str:
        return (
            f"{self._lcore_list} "
            f"{self._memory_channels} "
            f"{self._prefix} "
            f"{self._no_pci} "
            f"{self._vdevs} "
            f"{self._other_eal_param}"
        )
