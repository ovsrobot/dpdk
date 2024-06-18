# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 University of New Hampshire
# Copyright(c) 2023 PANTHEON.tech s.r.o.

"""Testpmd interactive shell.

Typical usage example in a TestSuite::

    testpmd_shell = self.sut_node.create_interactive_shell(
            TestPmdShell, privileged=True
        )
    devices = testpmd_shell.get_devices()
    for device in devices:
        print(device)
    testpmd_shell.close()
"""

import time
from enum import auto
from pathlib import PurePath
from typing import Callable, ClassVar

from framework.exception import InteractiveCommandExecutionError
from framework.settings import SETTINGS
from framework.utils import StrEnum

from .interactive_shell import InteractiveShell


class TestPmdDevice(object):
    """The data of a device that testpmd can recognize.

    Attributes:
        pci_address: The PCI address of the device.
    """

    pci_address: str

    def __init__(self, pci_address_line: str):
        """Initialize the device from the testpmd output line string.

        Args:
            pci_address_line: A line of testpmd output that contains a device.
        """
        self.pci_address = pci_address_line.strip().split(": ")[1].strip()

    def __str__(self) -> str:
        """The PCI address captures what the device is."""
        return self.pci_address


class TestPmdForwardingModes(StrEnum):
    r"""The supported packet forwarding modes for :class:`~TestPmdShell`\s."""

    #:
    io = auto()
    #:
    mac = auto()
    #:
    macswap = auto()
    #:
    flowgen = auto()
    #:
    rxonly = auto()
    #:
    txonly = auto()
    #:
    csum = auto()
    #:
    icmpecho = auto()
    #:
    ieee1588 = auto()
    #:
    noisy = auto()
    #:
    fivetswap = "5tswap"
    #:
    shared_rxq = "shared-rxq"
    #:
    recycle_mbufs = auto()


class TestPmdShell(InteractiveShell):
    """Testpmd interactive shell.

    The testpmd shell users should never use
    the :meth:`~.interactive_shell.InteractiveShell.send_command` method directly, but rather
    call specialized methods. If there isn't one that satisfies a need, it should be added.

    Attributes:
        number_of_ports: The number of ports which were allowed on the command-line when testpmd
            was started.
    """

    number_of_ports: int

    #: The path to the testpmd executable.
    path: ClassVar[PurePath] = PurePath("app", "dpdk-testpmd")

    #: Flag this as a DPDK app so that it's clear this is not a system app and
    #: needs to be looked in a specific path.
    dpdk_app: ClassVar[bool] = True

    #: The testpmd's prompt.
    _default_prompt: ClassVar[str] = "testpmd>"

    #: This forces the prompt to appear after sending a command.
    _command_extra_chars: ClassVar[str] = "\n"

    def _start_application(self, get_privileged_command: Callable[[str], str] | None) -> None:
        """Overrides :meth:`~.interactive_shell._start_application`.

        Add flags for starting testpmd in interactive mode and disabling messages for link state
        change events before starting the application. Link state is verified before starting
        packet forwarding and the messages create unexpected newlines in the terminal which
        complicates output collection.

        Also find the number of pci addresses which were allowed on the command line when the app
        was started.
        """
        self._app_args += " -i --mask-event intr_lsc"
        self.number_of_ports = self._app_args.count("-a ")
        super()._start_application(get_privileged_command)

    def start(self, verify: bool = True) -> None:
        """Start packet forwarding with the current configuration.

        Args:
            verify: If :data:`True` , a second start command will be sent in an attempt to verify
                packet forwarding started as expected.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and forwarding fails to
                start or ports fail to come up.
        """
        self.send_command("start")
        if verify:
            # If forwarding was already started, sending "start" again should tell us
            start_cmd_output = self.send_command("start")
            if "Packet forwarding already started" not in start_cmd_output:
                self._logger.debug(f"Failed to start packet forwarding: \n{start_cmd_output}")
                raise InteractiveCommandExecutionError("Testpmd failed to start packet forwarding.")

            for port_id in range(self.number_of_ports):
                if not self.wait_link_status_up(port_id):
                    raise InteractiveCommandExecutionError(
                        "Not all ports came up after starting packet forwarding in testpmd."
                    )

    def stop(self, verify: bool = True) -> None:
        """Stop packet forwarding.

        Args:
            verify: If :data:`True` , the output of the stop command is scanned to verify that
                forwarding was stopped successfully or not started. If neither is found, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the command to stop
                forwarding results in an error.
        """
        stop_cmd_output = self.send_command("stop")
        if verify:
            if (
                "Done." not in stop_cmd_output
                and "Packet forwarding not started" not in stop_cmd_output
            ):
                self._logger.debug(f"Failed to stop packet forwarding: \n{stop_cmd_output}")
                raise InteractiveCommandExecutionError("Testpmd failed to stop packet forwarding.")

    def get_devices(self) -> list[TestPmdDevice]:
        """Get a list of device names that are known to testpmd.

        Uses the device info listed in testpmd and then parses the output.

        Returns:
            A list of devices.
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
            timeout: Time to wait for the link to come up. The default value for this
                argument may be modified using the :option:`--timeout` command-line argument
                or the :envvar:`DTS_TIMEOUT` environment variable.

        Returns:
            Whether the link came up in time or not.
        """
        time_to_stop = time.time() + timeout
        port_info: str = ""
        while time.time() < time_to_stop:
            port_info = self.send_command(f"show port info {port_id}")
            if "Link status: up" in port_info:
                break
            time.sleep(0.5)
        else:
            self._logger.error(f"The link for port {port_id} did not come up in the given timeout.")
        return "Link status: up" in port_info

    def set_forward_mode(self, mode: TestPmdForwardingModes, verify: bool = True):
        """Set packet forwarding mode.

        Args:
            mode: The forwarding mode to use.
            verify: If :data:`True` the output of the command will be scanned in an attempt to
                verify that the forwarding mode was set to `mode` properly.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the forwarding mode
                fails to update.
        """
        set_fwd_output = self.send_command(f"set fwd {mode.value}")
        if f"Set {mode.value} packet forwarding mode" not in set_fwd_output:
            self._logger.debug(f"Failed to set fwd mode to {mode.value}:\n{set_fwd_output}")
            raise InteractiveCommandExecutionError(
                f"Test pmd failed to set fwd mode to {mode.value}"
            )

    def vlan_filter_set_on(self, port: int, verify: bool = True):
        """Set vlan filter on.

        Args:
            port: The port number to use, should be within 0-32.
            verify: If :data:`True`, the output of the command is scanned to verify that
                vlan filtering was enabled successfully. If not, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the filter
                fails to update.
        """
        filter_cmd_output = self.send_command(f"vlan set filter on {port}")
        if verify:
            if "Invalid port" in filter_cmd_output or "filter: on" not in self.send_command(f"show port info {port}"):
                self._logger.debug(f"Failed to enable vlan filter on port {port}: \n{filter_cmd_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to enable vlan filter on port {port}.")

    def vlan_filter_set_off(self, port: int, verify: bool = True):
        """Set vlan filter off.

        Args:
            port: The port number to use, should be within 0-32.
            verify: If :data:`True`, the output of the command is scanned to verify that
                vlan filtering was disabled successfully. If not, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the filter
                fails to update.
        """
        filter_cmd_output = self.send_command(f"vlan set filter off {port}")
        if verify:
            if "Invalid port" in filter_cmd_output or "filter: off" not in self.send_command(f"show port info {port}"):
                self._logger.debug(f"Failed to disable vlan filter on port {port}: \n{filter_cmd_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to disable vlan filter on port {port}.")

    def rx_vlan_add(self, vlan: int, port: int, verify: bool = True):
        """Add specified vlan tag to the filter list on a port.

        Args:
            vlan: The vlan tag to add, should be within 1-1005, 1-4094 extended.
            port: The port number to add the tag on, should be within 0-32.
            verify: If :data:`True`, the output of the command is scanned to verify that
                the vlan tag was added to the filter list on the specified port. If not, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the tag
            is not added.
        """
        vlan_add_output = self.send_command(f"rx_vlan add {vlan} {port}")
        if verify:
            if "VLAN-filtering disabled" in vlan_add_output or "Invalid vlan_id" in vlan_add_output:
                self._logger.debug(f"Failed to add vlan tag {vlan} on port {port}: \n{vlan_add_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to add vlan tag {vlan} on port {port}.")

    def rx_vlan_rm(self, vlan: int, port: int, verify: bool = True):
        """Remove specified vlan tag from filter list on a port.

        Args:
            vlan: The vlan tag to remove, should be within 1-4094.
            port: The port number to remove the tag from, should be within 0-32.
            verify: If :data:`True`, the output of the command is scanned to verify that
                the vlan tag was removed from the filter list on the specified port. If not, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the tag
            is not removed.
        """
        vlan_rm_output = self.send_command(f"rx_vlan rm {vlan} {port}")
        if verify:
            if "VLAN-filtering disabled" in vlan_rm_output or "Invalid vlan_id" in vlan_rm_output:
                self._logger.debug(f"Failed to remove vlan tag {vlan} on port {port}: \n{vlan_rm_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to remove vlan tag {vlan} on port {port}.")

    def vlan_strip_set_on(self, port: int, verify: bool = True):
        """Enable vlan stripping on the specified port.

        Args:
            port: The port number to use, should be within 0-32.
            verify: If :data:`True`, the output of the command is scanned to verify that
                vlan stripping was enabled on the specified port. If not, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and stripping
                fails to update.
        """
        vlan_strip_output = self.send_command(f"vlan set strip on {port}")
        if verify:
            if "strip on" not in self.send_command(f"show port info {port}"):
                self._logger.debug(f"Failed to set vlan filter on for port {port}: \n{vlan_strip_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to set vlan filter on for port {port}.")

    def vlan_strip_set_off(self, port: int, verify: bool = True):
        """Disable vlan stripping on the specified port.

        Args:
            port: The port number to use, should be within 0-32
            verify: If :data:`True`, the output of the command is scanned to verify that
                vlan stripping was disabled on the specified port. If not, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and stripping
                fails to update.
        """
        vlan_strip_output = self.send_command(f"vlan set strip off {port}")
        if verify:
            if "strip off" not in self.send_command(f"show port info {port}"):
                self._logger.debug(f"Failed to disable vlan stripping on port {port}: \n{vlan_strip_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to disable vlan stripping on port {port}.")

    def port_stop_all(self, verify: bool = True):
        """Stop all ports.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and all ports
                fail to stop."""
        port_output = self.send_command("port stop all")
        if verify:
            if "Done" not in port_output:
                self._logger.debug(f"Failed to stop all ports: \n{port_output}")
                raise InteractiveCommandExecutionError("Testpmd failed to stop all ports.")

    def port_stop(self, port: int, verify: bool = True):
        """Stop all ports.

        Args:
            port: specifies the port number to use, must be between 0-32

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the port
                is not stopped."""
        port_output = self.send_command(f"port stop {port}")
        if verify:
            if "Done" not in port_output:
                self._logger.debug(f"Failed to stop port {port}: \n{port_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to stop port {port}.")

    def port_start_all(self, verify: bool = True):
        """Start all ports.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and all ports
            fail to start."""
        port_output = self.send_command("port start all")
        if verify:
            if "Done" not in port_output:
                self._logger.debug(f"Failed to start all ports: \n{port_output}")
                raise InteractiveCommandExecutionError("Testpmd failed to start all ports.")

    def port_start(self, port: int, verify: bool = True):
        """Stop all ports.

        Args:
            port: specifies the port number to use, must be between 0-32

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the port
                is not started."""
        port_output = self.send_command(f"port start {port}")
        if verify:
            if "Done" not in port_output:
                self._logger.debug(f"Failed to start port {port}: \n{port_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to start port {port}.")


    def tx_vlan_set(self, port: int, vlan: int, verify: bool = True):
        """Set hardware insertion of vlan tags in packets sent on a port.

        Args:
            port: The port number to use, should be within 0-32.
            vlan: The vlan tag to insert, should be within 1-4094.
            verify: If :data:`True`, the output of the command is scanned to verify that
                vlan insertion was enabled on the specified port. If not, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the insertion
            tag is not set.
        """
        vlan_insert_output = self.send_command(f"tx_vlan set {port} {vlan}")
        if verify:
            if ("Please stop port" in vlan_insert_output or "Invalid vlan_id" in vlan_insert_output
            or "Invalid port" in vlan_insert_output):
                self._logger.debug(f"Failed to set vlan insertion tag {vlan} on port {port}: \n{vlan_insert_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to set vlan insertion tag {vlan} on port {port}.")

    def tx_vlan_reset(self, port: int, verify: bool = True):
        """Disable hardware insertion of vlan tags in packets sent on a port.

        Args:
            port: The port number to use, should be within 0-32.
            verify: If :data:`True`, the output of the command is scanned to verify that
                vlan insertion was disabled on the specified port. If not, it is
                considered an error.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the insertion
                tag is not reset.
        """
        vlan_insert_output = self.send_command(f"tx_vlan set {port}")
        if verify:
            if "Please stop port" in vlan_insert_output or "Invalid port" in vlan_insert_output:
                self._logger.debug(f"Failed to reset vlan insertion on port {port}: \n{vlan_insert_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to reset vlan insertion on port {port}.")

    def set_promisc(self, port: int, on: bool, verify: bool = True):
        """Turns promiscuous mode on/off for the specified port

        Args:
            port: port number to use, should be within 0-32.
            on: if :data:`True`, turn promisc mode on, otherwise turn off.
            verify: if :data:`True` an additional command will be sent to verify that promisc mode
                is properly set. Defaults to :data:`True`.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and promisc mode
            is not correctly set.
        """
        if on:
            promisc_output = self.send_command(f"set promisc {port} on")
        else:
            promisc_output = self.send_command(f"set promisc {port} off")
        if verify:
            if (on and "Promiscuous mode: enabled" not in
            self.send_command(f"show port info {port}")):
                self._logger.debug(f"Failed to set promisc mode on port {port}: \n{promisc_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to set promisc mode on port {port}.")
            elif (not on and "Promiscuous mode: disabled" not in
            self.send_command(f"show port info {port}")):
                self._logger.debug(f"Failed to set promisc mode on port {port}: \n{promisc_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to set promisc mode on port {port}.")


    def set_verbose(self, level: int, verify: bool = True):
        """Set debug verbosity level.

        Args:
            level: 0 - silent except for error
            1 - fully verbose except for Tx packets
            2 - fully verbose except for Rx packets
            >2 - fully verbose
            verify: if :data:`True` an additional command will be sent to verify that verbose level
                is properly set. Defaults to :data:`True`.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and verbose level
            is not correctly set.
        """
        verbose_output = self.send_command(f"set verbose {level}")
        if verify:
            if "Change verbose level" not in verbose_output:
                self._logger.debug(f"Failed to set verbose level to {level}: \n{verbose_output}")
                raise InteractiveCommandExecutionError(f"Testpmd failed to set verbose level to {level}.")

    def close(self) -> None:
        """Overrides :meth:`~.interactive_shell.close`."""
        self.send_command("quit", "")
        return super().close()
