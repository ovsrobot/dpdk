# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.
# Copyright(c) 2023 University of New Hampshire

"""Linux OS session interface.

Extends the base :class:`~.os_session.OSSession` with methods specific to Linux nodes.
The concrete implementation containing all backend logic lives in the framework package.
"""

from abc import ABC, abstractmethod


class LinuxSession(ABC):
    """Abstract interface for Linux-specific OS session operations.

    API consumers should type-hint against this class when they need access
    to Linux-only capabilities beyond the base :class:`~.os_session.OSSession` contract.
    """

    @abstractmethod
    def configure_ipv4_forwarding(self, enable: bool) -> None:
        """Enable or disable IPv4 forwarding on the node.

        Args:
            enable: True to enable forwarding, False to disable.
        """
