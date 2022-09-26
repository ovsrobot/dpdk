# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

from typing import Optional

from framework.config import NodeConfiguration
from framework.logger import DTSLOG, getLogger
from framework.remote_session import RemoteSession, create_remote_session
from framework.settings import SETTINGS

"""
A node is a generic host that DTS connects to and manages.
"""


class Node(object):
    """
    Basic module for node management. This module implements methods that
    manage a node, such as information gathering (of CPU/PCI/NIC) and
    environment setup.
    """

    main_session: RemoteSession
    name: str
    logger: DTSLOG
    _config: NodeConfiguration
    _other_sessions: list[RemoteSession]

    def __init__(self, node_config: NodeConfiguration):
        self._config = node_config
        self.name = node_config.name

        self.logger = getLogger(self.name)
        self.logger.info(f"Created node: {self.name}")
        self.main_session = create_remote_session(self._config, self.name, self.logger)
        self._other_sessions = []

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

    def send_command(self, cmds: str, timeout: float = SETTINGS.timeout) -> str:
        """
        Send commands to node and return string before timeout.
        """

        return self.main_session.send_command(cmds, timeout)

    def create_session(self, name: str) -> RemoteSession:
        connection = create_remote_session(
            self._config,
            name,
            getLogger(name, node=self.name),
        )
        self._other_sessions.append(connection)
        return connection

    def node_exit(self) -> None:
        """
        Recover all resource before node exit
        """
        if self.main_session:
            self.main_session.close()
        for session in self._other_sessions:
            session.close()
        self.logger.logger_exit()
