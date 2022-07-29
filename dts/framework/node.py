# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

from typing import Optional

from .config import NodeConfiguration
from .logger import DTSLOG, getLogger
from .settings import SETTINGS
from .ssh_connection import SSHConnection

"""
A node is a generic host that DTS connects to and manages.
"""


class Node(object):
    """
    Basic module for node management. This module implements methods that
    manage a node, such as information gathering (of CPU/PCI/NIC) and
    environment setup.
    """

    _config: NodeConfiguration
    logger: DTSLOG
    main_session: SSHConnection
    name: str
    _other_sessions: list[SSHConnection]

    def __init__(self, node_config: NodeConfiguration):
        self._config = node_config
        self.name = node_config.name

        self.logger = getLogger(self.name)
        self.logger.info(f"Created node: {self.name}")
        self.main_session = SSHConnection(
            self.get_ip_address(),
            self.name,
            self.logger,
            self.get_username(),
            self.get_password(),
        )

    def get_ip_address(self) -> str:
        """
        Get SUT's ip address.
        """
        return self._config.hostname

    def get_password(self) -> Optional[str]:
        """
        Get SUT's login password.
        """
        return self._config.password

    def get_username(self) -> str:
        """
        Get SUT's login username.
        """
        return self._config.user

    def send_expect(
        self,
        command: str,
        expected: str,
        timeout: float = SETTINGS.timeout,
        verify: bool = False,
        trim_whitespace: bool = True,
    ) -> str | int:
        """
        Send commands to node and return string before expected string. If
        there's no expected string found before timeout, TimeoutException will
        be raised.

        By default, it will trim the whitespace from the expected string. This
        behavior can be turned off via the trim_whitespace argument.
        """

        if trim_whitespace:
            expected = expected.strip()

        return self.main_session.send_expect(command, expected, timeout, verify)

    def send_command(self, cmds: str, timeout: float = SETTINGS.timeout) -> str:
        """
        Send commands to node and return string before timeout.
        """

        return self.main_session.send_command(cmds, timeout)

    def node_exit(self) -> None:
        """
        Recover all resource before node exit
        """
        if self.main_session:
            self.main_session.close()
        self.logger.logger_exit()
