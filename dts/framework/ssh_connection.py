# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import dataclasses
from typing import Any, Optional

from .logger import DTSLOG
from .ssh_pexpect import SSHPexpect


@dataclasses.dataclass(slots=True, frozen=True)
class HistoryRecord:
    command: str
    name: str
    output: str | int


class SSHConnection(object):
    """
    Module for create session to node.
    """

    name: str
    history: list[HistoryRecord]
    logger: DTSLOG
    session: SSHPexpect | Any

    def __init__(
        self,
        node: str,
        session_name: str,
        logger: DTSLOG,
        username: str,
        password: Optional[str] = "",
    ):
        self.session = SSHPexpect(node, username, password, logger)
        self.name = session_name
        self.history = []
        self.logger = logger

    def send_expect(
        self, cmds: str, expected: str, timeout: float = 15, verify: bool = False
    ) -> str | int:
        self.logger.info(cmds)
        out = self.session.send_expect(cmds, expected, timeout, verify)
        if isinstance(out, str):
            self.logger.debug(out.replace(cmds, ""))
        self.history.append(HistoryRecord(command=cmds, name=self.name, output=out))
        return out

    def send_command(self, cmds: str, timeout: float = 1) -> str:
        self.logger.info(cmds)
        out = self.session.send_command(cmds, timeout)
        self.logger.debug(out.replace(cmds, ""))
        self.history.append(HistoryRecord(command=cmds, name=self.name, output=out))
        return out

    def get_session_before(self, timeout: float = 15) -> str:
        out = self.session.get_session_before(timeout)
        self.logger.debug(out)
        return out

    def close(self, force: bool = False) -> None:
        if getattr(self, "logger", None):
            self.logger.logger_exit()

        self.session.close(force)
