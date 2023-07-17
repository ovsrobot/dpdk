# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire

from pathlib import PurePath
from typing import Callable

from paramiko import Channel, SSHClient, channel  # type: ignore

from framework.logger import DTSLOG
from framework.settings import SETTINGS


class InteractiveShell:

    _interactive_session: SSHClient
    _stdin: channel.ChannelStdinFile
    _stdout: channel.ChannelFile
    _ssh_channel: Channel
    _logger: DTSLOG
    _timeout: float
    _startup_command: str
    _app_args: str
    _default_prompt: str = ""
    _privileged: bool
    _get_privileged_command: Callable[[str], str]
    # Allows for app specific extra characters to be appended to commands
    _command_extra_chars: str = ""
    path: PurePath
    dpdk_app: bool = False

    def __init__(
        self,
        interactive_session: SSHClient,
        logger: DTSLOG,
        startup_command: str,
        privileged: bool,
        _get_privileged_command: Callable[[str], str],
        app_args: str = "",
        timeout: float = SETTINGS.timeout,
    ) -> None:
        self._interactive_session = interactive_session
        self._ssh_channel = self._interactive_session.invoke_shell()
        self._stdin = self._ssh_channel.makefile_stdin("w")
        self._stdout = self._ssh_channel.makefile("r")
        self._ssh_channel.settimeout(timeout)
        self._ssh_channel.set_combine_stderr(True)  # combines stdout and stderr streams
        self._logger = logger
        self._timeout = timeout
        self._startup_command = startup_command
        self._app_args = app_args
        self._get_privileged_command = _get_privileged_command  # type: ignore
        self._privileged = privileged
        self._start_application()

    def _start_application(self) -> None:
        """Starts a new interactive application based on _startup_command.

        This method is often overridden by subclasses as their process for
        starting may look different.
        """
        start_command = f"{self._startup_command} {self._app_args}"
        if self._privileged:
            start_command = self._get_privileged_command(start_command)  # type: ignore
        self.send_command(start_command)

    def send_command(self, command: str, prompt: str | None = None) -> str:
        """Send a command and get all output before the expected ending string.

        Lines that expect input are not included in the stdout buffer so they cannot be
        used for expect. For example, if you were prompted to log into something
        with a username and password, you cannot expect "username:" because it won't
        yet be in the stdout buffer. A work around for this could be consuming an
        extra newline character to force the current prompt into the stdout buffer.

        Returns:
            All output in the buffer before expected string
        """
        self._logger.info(f"Sending command {command.strip()}...")
        if prompt is None:
            prompt = self._default_prompt
        self._stdin.write(f"{command}{self._command_extra_chars}\n")
        self._stdin.flush()
        out: str = ""
        for line in self._stdout:
            out += line
            if prompt in line and not line.rstrip().endswith(
                command.rstrip()
            ):  # ignore line that sent command
                break
        self._logger.debug(f"Got output: {out}")
        return out

    def close(self) -> None:
        self._stdin.close()
        self._ssh_channel.close()

    def __del__(self) -> None:
        self.close()
