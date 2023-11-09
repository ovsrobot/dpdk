# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire

import time
from pathlib import PurePath
from typing import Callable

from framework.settings import SETTINGS

from .interactive_shell import InteractiveShell


class TestPmdDevice(object):
    pci_address: str

    def __init__(self, pci_address_line: str):
        self.pci_address = pci_address_line.strip().split(": ")[1].strip()

    def __str__(self) -> str:
        return self.pci_address


class TestPmdShell(InteractiveShell):
    path: PurePath = PurePath("app", "dpdk-testpmd")
    dpdk_app: bool = True
    _default_prompt: str = "testpmd>"
    _command_extra_chars: str = (
        "\n"  # We want to append an extra newline to every command
    )

    def _start_application(
        self, get_privileged_command: Callable[[str], str] | None
    ) -> None:
        """See "_start_application" in InteractiveShell."""
        self._app_args += " -i"
        super()._start_application(get_privileged_command)

    def get_devices(self) -> list[TestPmdDevice]:
        """Get a list of device names that are known to testpmd

        Uses the device info listed in testpmd and then parses the output to
        return only the names of the devices.

        Returns:
            A list of strings representing device names (e.g. 0000:14:00.1)
        """
        dev_info: str = self.send_command("show device info all")
        dev_list: list[TestPmdDevice] = []
        for line in dev_info.split("\n"):
            if "device name:" in line.lower():
                dev_list.append(TestPmdDevice(line))
        return dev_list

    def wait_link_status_up(self, port_id: int, timeout=SETTINGS.timeout) -> bool:
        """Wait until the link status on the given port is "up".

        Arguments:
            port_id: Port to check the link status on.
            timeout: time to wait for the link to come up.

        Returns:
            If the link came up in time or not.
        """
        time_to_stop = time.time() + timeout
        while time.time() < time_to_stop:
            port_info = self.send_command(f"show port info {port_id}")
            if "Link status: up" in port_info:
                break
            time.sleep(0.5)
        else:
            self._logger.error(
                f"The link for port {port_id} did not come up in the given timeout."
            )
        return "Link status: up" in port_info

    def close(self) -> None:
        self.send_command("exit", "")
        return super().close()
