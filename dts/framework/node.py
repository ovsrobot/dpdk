# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
#

from .logger import getLogger
from .settings import TIMEOUT
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

    def __init__(self, node, sut_id=0, name=None):
        self.node = node

        self.logger = getLogger(name)
        self.session = SSHConnection(
            self.get_ip_address(),
            name,
            self.get_username(),
            self.get_password(),
            sut_id,
        )
        self.session.init_log(self.logger)

    def get_ip_address(self):
        """
        Get SUT's ip address.
        """
        return self.node["IP"]

    def get_password(self):
        """
        Get SUT's login password.
        """
        return self.node["pass"]

    def get_username(self):
        """
        Get SUT's login username.
        """
        return self.node["user"]

    def send_expect(
        self,
        cmds,
        expected,
        timeout=TIMEOUT,
        verify=False,
        trim_whitespace=True,
    ):
        """
        Send commands to node and return string before expected string. If
        there's no expected string found before timeout, TimeoutException will
        be raised.

        By default, it will trim the whitespace from the expected string. This
        behavior can be turned off via the trim_whitespace argument.
        """

        if trim_whitespace:
            expected = expected.strip()

        return self.session.send_expect(cmds, expected, timeout, verify)

    def send_command(self, cmds, timeout=TIMEOUT):
        """
        Send commands to node and return string before timeout.
        """

        return self.session.send_command(cmds, timeout)

    def close(self):
        """
        Close ssh session of SUT.
        """
        if self.session:
            self.session.close()
            self.session = None

    def node_exit(self):
        """
        Recover all resource before node exit
        """
        self.close()
        self.logger.logger_exit()
