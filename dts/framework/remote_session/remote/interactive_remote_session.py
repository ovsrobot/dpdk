# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire

import socket
import traceback
from pathlib import PurePath
from typing import Union

from paramiko import AutoAddPolicy, SSHClient, Transport  # type: ignore
from paramiko.ssh_exception import (  # type: ignore
    AuthenticationException,
    BadHostKeyException,
    NoValidConnectionsError,
    SSHException,
)

from framework.config import InteractiveApp, NodeConfiguration
from framework.exception import SSHConnectionError
from framework.logger import DTSLOG

from .interactive_shell import InteractiveShell
from .testpmd_shell import TestPmdShell


class InteractiveRemoteSession:
    hostname: str
    ip: str
    port: int
    username: str
    password: str
    _logger: DTSLOG
    _node_config: NodeConfiguration
    session: SSHClient
    _transport: Transport | None

    def __init__(self, node_config: NodeConfiguration, _logger: DTSLOG) -> None:
        self._node_config = node_config
        self._logger = _logger
        self.hostname = node_config.hostname
        self.username = node_config.user
        self.password = node_config.password if node_config.password else ""
        port = "22"
        self.ip = node_config.hostname
        if ":" in node_config.hostname:
            self.ip, port = node_config.hostname.split(":")
        self.port = int(port)
        self._logger.info(
            f"Initializing interactive connection for {self.username}@{self.hostname}"
        )
        self._connect()
        self._logger.info(
            f"Interactive connection successful for {self.username}@{self.hostname}"
        )

    def _connect(self) -> None:
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy)
        self.session = client
        retry_attempts = 10
        for retry_attempt in range(retry_attempts):
            try:
                client.connect(
                    self.ip,
                    username=self.username,
                    port=self.port,
                    password=self.password,
                    timeout=20 if self.port else 10,
                )
            except (TypeError, BadHostKeyException, AuthenticationException) as e:
                self._logger.exception(e)
                raise SSHConnectionError(self.hostname) from e
            except (NoValidConnectionsError, socket.error, SSHException) as e:
                self._logger.debug(traceback.format_exc())
                self._logger.warning(e)
                self._logger.info(
                    "Retrying interactive session connection: "
                    f"retry number {retry_attempt +1}"
                )
            else:
                break
        else:
            raise SSHConnectionError(self.hostname)
        # Interactive sessions are used on an "as needed" basis so we have
        # to set a keepalive
        self._transport = self.session.get_transport()
        if self._transport is not None:
            self._transport.set_keepalive(30)

    def create_interactive_shell(
        self,
        shell_type: InteractiveApp,
        path_to_app: PurePath,
        eal_parameters: str,
        timeout: float,
    ) -> Union[InteractiveShell, TestPmdShell]:
        """
        See "create_interactive_shell" in SutNode
        """
        match (shell_type):
            case InteractiveApp.shell:
                return InteractiveShell(
                    self.session, self._logger, path_to_app, timeout
                )
            case InteractiveApp.testpmd:
                return TestPmdShell(
                    self.session,
                    self._logger,
                    path_to_app,
                    timeout=timeout,
                    eal_flags=eal_parameters,
                )
            case _:
                self._logger.info(
                    f"Unhandled app type {shell_type.name}, defaulting to shell."
                )
                return InteractiveShell(
                    self.session, self._logger, path_to_app, timeout
                )
