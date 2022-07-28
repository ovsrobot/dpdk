# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#

import time
from typing import Optional

from pexpect import pxssh

from .exception import SSHConnectionException, SSHSessionDeadException, TimeoutException
from .logger import DTSLOG
from .utils import GREEN, RED

"""
The module handles ssh sessions to TG and SUT.
It implements the send_expect function to send commands and get output data.
"""


class SSHPexpect:
    username: str
    password: str
    node: str
    logger: DTSLOG
    magic_prompt: str

    def __init__(
        self,
        node: str,
        username: str,
        password: Optional[str],
        logger: DTSLOG,
    ):
        self.magic_prompt = "MAGIC PROMPT"
        self.logger = logger

        self.node = node
        self.username = username
        self.password = password or ""
        self.logger.info(f"ssh {self.username}@{self.node}")

        self._connect_host()

    def _connect_host(self) -> None:
        """
        Create connection to assigned node.
        """
        retry_times = 10
        try:
            if ":" in self.node:
                while retry_times:
                    self.ip = self.node.split(":")[0]
                    self.port = int(self.node.split(":")[1])
                    self.session = pxssh.pxssh(encoding="utf-8")
                    try:
                        self.session.login(
                            self.ip,
                            self.username,
                            self.password,
                            original_prompt="[$#>]",
                            port=self.port,
                            login_timeout=20,
                            password_regex=r"(?i)(?:password:)|(?:passphrase for key)|(?i)(password for .+:)",
                        )
                    except Exception as e:
                        print(e)
                        time.sleep(2)
                        retry_times -= 1
                        print("retry %d times connecting..." % (10 - retry_times))
                    else:
                        break
                else:
                    raise Exception("connect to %s:%s failed" % (self.ip, self.port))
            else:
                self.session = pxssh.pxssh(encoding="utf-8")
                self.session.login(
                    self.node,
                    self.username,
                    self.password,
                    original_prompt="[$#>]",
                    password_regex=r"(?i)(?:password:)|(?:passphrase for key)|(?i)(password for .+:)",
                )
                self.logger.info(f"Connection to {self.node} succeeded")
            self.send_expect("stty -echo", "#")
            self.send_expect("stty columns 1000", "#")
        except Exception as e:
            print(RED(str(e)))
            if getattr(self, "port", None):
                suggestion = (
                    "\nSuggession: Check if the firewall on [ %s ] " % self.ip
                    + "is stopped\n"
                )
                print(GREEN(suggestion))

            raise SSHConnectionException(self.node)

    def send_expect_base(self, command: str, expected: str, timeout: float) -> str:
        self.clean_session()
        self.session.PROMPT = expected
        self.__sendline(command)
        self.__prompt(command, timeout)

        before = self.get_output_before()
        return before

    def send_expect(
        self, command: str, expected: str, timeout: float = 15, verify: bool = False
    ) -> str | int:

        try:
            ret = self.send_expect_base(command, expected, timeout)
            if verify:
                ret_status = self.send_expect_base("echo $?", expected, timeout)
                if not int(ret_status):
                    return ret
                else:
                    self.logger.error("Command: %s failure!" % command)
                    self.logger.error(ret)
                    return int(ret_status)
            else:
                return ret
        except Exception as e:
            print(
                RED(
                    "Exception happened in [%s] and output is [%s]"
                    % (command, self.get_output_before())
                )
            )
            raise e

    def send_command(self, command: str, timeout: float = 1) -> str:
        try:
            self.clean_session()
            self.__sendline(command)
        except Exception as e:
            raise e

        output = self.get_session_before(timeout=timeout)
        self.session.PROMPT = self.session.UNIQUE_PROMPT
        self.session.prompt(0.1)

        return output

    def clean_session(self) -> None:
        self.get_session_before(timeout=0.01)

    def get_session_before(self, timeout: float = 15) -> str:
        """
        Get all output before timeout
        """
        self.session.PROMPT = self.magic_prompt
        try:
            self.session.prompt(timeout)
        except Exception as e:
            pass

        before = self.get_output_all()
        self.__flush()

        return before

    def __flush(self) -> None:
        """
        Clear all session buffer
        """
        self.session.buffer = ""
        self.session.before = ""

    def __prompt(self, command: str, timeout: float) -> None:
        if not self.session.prompt(timeout):
            raise TimeoutException(command, self.get_output_all()) from None

    def __sendline(self, command: str) -> None:
        if not self.isalive():
            raise SSHSessionDeadException(self.node)
        if len(command) == 2 and command.startswith("^"):
            self.session.sendcontrol(command[1])
        else:
            self.session.sendline(command)

    def get_output_before(self) -> str:
        if not self.isalive():
            raise SSHSessionDeadException(self.node)
        before: list[str] = self.session.before.rsplit("\r\n", 1)
        if before[0] == "[PEXPECT]":
            before[0] = ""

        return before[0]

    def get_output_all(self) -> str:
        output: str = self.session.before
        output.replace("[PEXPECT]", "")
        return output

    def close(self, force: bool = False) -> None:
        if force is True:
            self.session.close()
        else:
            if self.isalive():
                self.session.logout()

    def isalive(self) -> bool:
        return self.session.isalive()
