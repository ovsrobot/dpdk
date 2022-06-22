# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
#

from .ssh_pexpect import SSHPexpect


class SSHConnection(object):

    """
    Module for create session to node.
    """

    def __init__(self, node, session_name, username, password="", sut_id=0):
        self.session = SSHPexpect(node, username, password, sut_id)
        self.name = session_name
        self.history = None

    def init_log(self, logger):
        self.logger = logger
        self.session.init_log(logger)

    def set_history(self, history):
        self.history = history

    def send_expect(self, cmds, expected, timeout=15, verify=False):
        self.logger.info(cmds)
        out = self.session.send_expect(cmds, expected, timeout, verify)
        if isinstance(out, str):
            self.logger.debug(out.replace(cmds, ""))
        if type(self.history) is list:
            self.history.append({"command": cmds, "name": self.name, "output": out})
        return out

    def send_command(self, cmds, timeout=1):
        self.logger.info(cmds)
        out = self.session.send_command(cmds, timeout)
        self.logger.debug(out.replace(cmds, ""))
        if type(self.history) is list:
            self.history.append({"command": cmds, "name": self.name, "output": out})
        return out

    def get_session_before(self, timeout=15):
        out = self.session.get_session_before(timeout)
        self.logger.debug(out)
        return out

    def close(self, force=False):
        if getattr(self, "logger", None):
            self.logger.logger_exit()

        self.session.close(force)
