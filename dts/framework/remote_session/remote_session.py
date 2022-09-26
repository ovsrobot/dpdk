# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import dataclasses
from abc import ABC, abstractmethod
from typing import Optional

from framework.config import NodeConfiguration
from framework.logger import DTSLOG
from framework.settings import SETTINGS


@dataclasses.dataclass(slots=True, frozen=True)
class HistoryRecord:
    command: str
    name: str
    output: str | int


class RemoteSession(ABC):
    _node_config: NodeConfiguration
    hostname: str
    username: str
    password: str
    ip: str
    port: Optional[int]
    name: str
    logger: DTSLOG
    history: list[HistoryRecord]

    def __init__(
        self,
        node_config: NodeConfiguration,
        session_name: str,
        logger: DTSLOG,
    ):
        self._node_config = node_config
        self.logger = logger
        self.name = session_name

        self.hostname = node_config.hostname
        self.ip = self.hostname
        self.port = None
        if ":" in self.hostname:
            self.ip, port = self.hostname.split(":")
            self.port = int(port)

        self.username = node_config.user
        self.password = node_config.password or ""
        self.logger.info(f"Remote {self.username}@{self.hostname}")
        self.history = []

        self._connect()

    def _history_add(self, command: str, output: str) -> None:
        self.history.append(
            HistoryRecord(command=command, name=self.name, output=output)
        )

    def send_command(self, command: str, timeout: float = SETTINGS.timeout) -> str:
        self.logger.info(f"Sending: {command}")
        out = self._send_command(command, timeout)
        self.logger.debug(f"Received from {command}: {out}")
        self._history_add(command=command, output=out)
        return out

    def close(self, force: bool = False) -> None:
        self.logger.logger_exit()
        self._close(force)

    @abstractmethod
    def _connect(self) -> None:
        """
        Create connection to assigned node.
        """
        pass

    @abstractmethod
    def _send_command(self, command: str, timeout: float) -> str:
        """
        Send a command and return the output.
        """
        pass

    @abstractmethod
    def _close(self, force: bool = False) -> None:
        """
        Close the remote session, freeing all used resources.
        """
        pass

    @abstractmethod
    def is_alive(self) -> bool:
        """
        Check whether the session is still responding.
        """
        pass
