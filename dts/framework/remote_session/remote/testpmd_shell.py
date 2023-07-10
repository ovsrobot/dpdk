# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire


from pathlib import PurePath

from paramiko import SSHClient  # type: ignore

from framework.logger import DTSLOG
from framework.settings import SETTINGS

from .interactive_shell import InteractiveShell


class TestPmdShell(InteractiveShell):
    expected_prompt: str = "testpmd>"
    _eal_flags: str

    def __init__(
        self,
        interactive_session: SSHClient,
        logger: DTSLOG,
        path_to_testpmd: PurePath,
        eal_flags: str,
        timeout: float = SETTINGS.timeout,
    ) -> None:
        """Initializes an interactive testpmd session using specified parameters."""
        self._eal_flags = eal_flags

        super(TestPmdShell, self).__init__(
            interactive_session,
            logger=logger,
            path_to_app=path_to_testpmd,
            timeout=timeout,
        )
        self._start_application()

    def _start_application(self) -> None:
        """Starts a new interactive testpmd shell using _path_to_app.
        """
        self.send_command(
            f"{self._path_to_app} {self._eal_flags} -- -i",
        )

    def send_command(self, command: str, prompt: str = expected_prompt) -> str:
        """Specific way of handling the command for testpmd

        An extra newline character is consumed in order to force the current line into
        the stdout buffer.
        """
        return self.send_command_get_output(f"{command}\n", prompt)

    def get_devices(self) -> list[str]:
        """Get a list of device names that are known to testpmd

        Uses the device info listed in testpmd and then parses the output to
        return only the names of the devices.

        Returns:
            A list of strings representing device names (e.g. 0000:14:00.1)
        """
        dev_info: str = self.send_command("show device info all")
        dev_list: list[str] = []
        for line in dev_info.split("\n"):
            if "device name:" in line.lower():
                dev_list.append(line.strip().split(": ")[1].strip())
        return dev_list
