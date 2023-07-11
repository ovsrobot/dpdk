# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire

import socket
import traceback

from paramiko import AutoAddPolicy, SSHClient, Transport  # type: ignore
from paramiko.ssh_exception import (  # type: ignore
    AuthenticationException,
    BadHostKeyException,
    NoValidConnectionsError,
    SSHException,
)

from framework.config import NodeConfiguration
from framework.exception import SSHConnectionError
from framework.logger import DTSLOG


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
