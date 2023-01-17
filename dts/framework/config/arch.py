# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.


class Arch(object):
    """
    Stores architecture-specific information.
    """

    @property
    def default_hugepage_memory(self) -> int:
        """
        Return the default amount of memory allocated for hugepages DPDK will use.
        The default is an amount equal to 256 2MB hugepages (512MB memory).
        """
        return 256 * 2048

    @property
    def hugepage_force_first_numa(self) -> bool:
        """
        An architecture may need to force configuration of hugepages to first socket.
        """
        return False


class x86_64(Arch):
    @property
    def default_hugepage_memory(self) -> int:
        return 4096 * 2048


class x86_32(Arch):
    @property
    def hugepage_force_first_numa(self) -> bool:
        return True


class i686(Arch):
    @property
    def default_hugepage_memory(self) -> int:
        return 512 * 2048

    @property
    def hugepage_force_first_numa(self) -> bool:
        return True


class PPC64(Arch):
    @property
    def default_hugepage_memory(self) -> int:
        return 512 * 2048


class Arm64(Arch):
    @property
    def default_hugepage_memory(self) -> int:
        return 2048 * 2048
