# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.
# Copyright(c) 2023 University of New Hampshire
"""Linux OS session interface.

Extends the base :class:`~.os_session.OSSession` with methods specific to Linux nodes.
The concrete implementation containing all backend logic lives in the framework package.
"""

from abc import ABC, abstractmethod
from pathlib import PurePath


class LinuxSession(ABC):
    """Abstract interface for Linux-specific OS session operations."""

    @property
    @abstractmethod
    def devbind_script_path(self) -> PurePath:
        """The path to the devbind script."""

    @devbind_script_path.setter
    @abstractmethod
    def devbind_script_path(self, value: PurePath) -> None:
        """Set the devbind script path after environment setup."""

    @abstractmethod
    def set_interface_link_up(self, name: str) -> None:
        """Set the link status of an interface to up.

        Args:
            name: The name of the interface.
        """

    @abstractmethod
    def delete_interface(self, name: str) -> None:
        """Delete a virtual interface.

        Args:
            name: The name of the interface to delete.
        """
