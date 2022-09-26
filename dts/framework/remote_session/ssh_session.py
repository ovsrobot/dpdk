# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 PANTHEON.tech s.r.o.
# Copyright(c) 2022 University of New Hampshire
#


import time

from pexpect import pxssh

from framework.config import NodeConfiguration
from framework.exception import (
    SSHConnectionException,
    SSHSessionDeadException,
    TimeoutException,
)
from framework.logger import DTSLOG
from framework.utils import GREEN, RED

from .remote_session import RemoteSession


class SSHSession(RemoteSession):
    """
    Module for creating Pexpect SSH sessions to a node.
    """

    session: pxssh.pxssh
    magic_prompt: str

    def __init__(
        self,
        node_config: NodeConfiguration,
        session_name: str,
        logger: DTSLOG,
    ):
        self.magic_prompt = "MAGIC PROMPT"
        super(SSHSession, self).__init__(node_config, session_name, logger)

    def _connect(self) -> None:
        """
        Create connection to assigned node.
        """
        retry_attempts = 10
        login_timeout = 20 if self.port else 10
        password_regex = (
            r"(?i)(?:password:)|(?:passphrase for key)|(?i)(password for .+:)"
        )
        try:
            for retry_attempt in range(retry_attempts):
                self.session = pxssh.pxssh(encoding="utf-8")
                try:
                    self.session.login(
                        self.ip,
                        self.username,
                        self.password,
                        original_prompt="[$#>]",
                        port=self.port,
                        login_timeout=login_timeout,
                        password_regex=password_regex,
                    )
                    break
                except Exception as e:
                    print(e)
                    time.sleep(2)
                    print(f"Retrying connection: retry number {retry_attempt + 1}.")
            else:
                raise Exception(f"Connection to {self.hostname} failed")

            self.logger.info(f"Connection to {self.hostname} succeeded")
            self.send_expect("stty -echo", "#")
            self.send_expect("stty columns 1000", "#")
        except Exception as e:
            print(RED(str(e)))
            if getattr(self, "port", None):
                suggestion = (
                    f"\nSuggestion: Check if the firewall on {self.hostname} is "
                    f"stopped.\n"
                )
                print(GREEN(suggestion))

            raise SSHConnectionException(self.hostname)

    def send_expect_base(self, command: str, prompt: str, timeout: float) -> str:
        self.clean_session()
        original_prompt = self.session.PROMPT
        self.session.PROMPT = prompt
        self.__sendline(command)
        self.__prompt(command, timeout)

        before = self._get_output()
        self.session.PROMPT = original_prompt
        return before

    def send_expect(
        self, command: str, prompt: str, timeout: float = 15, verify: bool = False
    ) -> str | int:
        try:
            ret = self.send_expect_base(command, prompt, timeout)
            if verify:
                ret_status = self.send_expect_base("echo $?", prompt, timeout)
                try:
                    retval = int(ret_status)
                    if not retval:
                        self.logger.error(f"Command: {command} failure!")
                        self.logger.error(ret)
                        return retval
                    else:
                        return ret
                except ValueError:
                    return ret
            else:
                return ret
        except Exception as e:
            print(
                f"Exception happened in [{command}] and output is "
                f"[{self._get_output()}]"
            )
            raise e

    def _send_command(self, command: str, timeout: float = 1) -> str:
        try:
            self.clean_session()
            self.__sendline(command)
        except Exception as e:
            raise e

        output = self.get_output(timeout=timeout)
        self.session.PROMPT = self.session.UNIQUE_PROMPT
        self.session.prompt(0.1)

        return output

    def clean_session(self) -> None:
        self.get_output(timeout=0.01)

    def _get_output(self) -> str:
        if not self.is_alive():
            raise SSHSessionDeadException(self.hostname)
        before = self.session.before.rsplit("\r\n", 1)[0]
        if before == "[PEXPECT]":
            return ""
        return before

    def get_output(self, timeout: float = 15) -> str:
        """
        Get all output before timeout
        """
        self.session.PROMPT = self.magic_prompt
        try:
            self.session.prompt(timeout)
        except Exception:
            pass

        before = self._get_output()
        self.__flush()

        self.logger.debug(before)
        return before

    def __flush(self) -> None:
        """
        Clear all session buffer
        """
        self.session.buffer = ""
        self.session.before = ""

    def __prompt(self, command: str, timeout: float) -> None:
        if not self.session.prompt(timeout):
            raise TimeoutException(command, self._get_output()) from None

    def __sendline(self, command: str) -> None:
        if not self.is_alive():
            raise SSHSessionDeadException(self.hostname)
        if len(command) == 2 and command.startswith("^"):
            self.session.sendcontrol(command[1])
        else:
            self.session.sendline(command)

    def _close(self, force: bool = False) -> None:
        if force is True:
            self.session.close()
        else:
            if self.is_alive():
                self.session.logout()

    def is_alive(self) -> bool:
        return self.session.isalive()
