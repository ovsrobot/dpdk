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

    def stop(self, verify: bool = True) -> str:
        """Stop packet forwarding.

        Args:
            verify: If :data:`True` , the output of the stop command is scanned to verify that
                forwarding was stopped successfully or not started. If neither is found, it is
                considered an error.

        Returns:
            Output gathered from sending the stop command.

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
        return stop_cmd_output

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

    def stop_port_queue(
        self,
        port_id: int,
        queue_id: int,
        is_rx_queue: bool,
        verify: bool = True
    ) -> None:
        """Stops a given queue on a port.

        Args:
            port_id: ID of the port that the queue belongs to.
            queue_id: ID of the queue to stop.
            is_rx_queue: Type of queue to stop. If :data:`True` an RX queue will be stopped,
                otherwise a TX queue will be stopped.
            verify: If :data:`True` an additional command will be sent to verify the queue stopped.
                Defaults to :data:`True`.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the queue fails
                to stop.
        """
        port_type = "rxq" if is_rx_queue else "txq"
        stop_cmd_output = self.send_command(f"port {port_id} {port_type} {queue_id} stop")
        if verify:
            if (
                # Rx/Tx queue state: ...
                f"{port_type.capitalize()[:-1]} queue state: stopped" not in
                self.send_command(f"show {port_type} info {port_id} {queue_id}")
            ):
                self._logger.debug(
                    f"Failed to stop {port_type} {queue_id} on port {port_id}:\n{stop_cmd_output}"
                )
                raise InteractiveCommandExecutionError(
                    f"Test pmd failed to stop {port_type} {queue_id} on port {port_id}"
                )

    def start_port_queue(
        self,
        port_id: int,
        queue_id: int,
        is_rx_queue: bool,
        verify: bool = True
    ) -> None:
        """Starts a given RX queue on a port.

        Args:
            port_id: ID of the port that the queue belongs to.
            queue_id: ID of the queue to start.
            is_rx_queue: Type of queue to start. If :data:`True` an RX queue will be started,
                otherwise a TX queue will be started.
            verify: if :data:`True` an additional command will be sent to verify that the queue was
                started. Defaults to :data:`True`.

        Raises:
            InteractiveCommandExecutionError: If `verify` is :data:`True` and the queue fails to
                start.
        """
        port_type = "rxq" if is_rx_queue else "txq"
        self.setup_port_queue(port_id, queue_id, port_type)
        start_cmd_output = self.send_command(f"port {port_id} {port_type} {queue_id} start")
        if verify:
            if (
                # Rx/Tx queue state: ...
                f"{port_type.capitalize()[:-1]} queue state: started" not in
                self.send_command(f"show {port_type} info {port_id} {queue_id}")
            ):
                self._logger.debug(
                    f"Failed to start {port_type} {queue_id} on port {port_id}:\n{start_cmd_output}"
                )
                raise InteractiveCommandExecutionError(
                    f"Test pmd failed to start {port_type} {queue_id} on port {port_id}"
                )

    def setup_port_queue(self, port_id: int, queue_id: int, is_rx_queue: bool) -> None:
        """Setup a given queue on a port.

        This functionality cannot be verified because the setup action only takes effect when the
        queue is started.

        Args:
            port_id: ID of the port where the queue resides.
            queue_id: ID of the queue to setup.
            is_rx_queue: Type of queue to setup. If :data:`True` an RX queue will be setup,
                otherwise a TX queue will be setup.
        """
        self.send_command(f"port {port_id} {'rxq' if is_rx_queue else 'txq'} {queue_id} setup")

    def change_queue_ring_size(
            self,
            port_id: int,
            queue_id: int,
            size: int,
            is_rx_queue: bool,
            verify: bool = True,
        ) -> None:
            """Update the ring size of an RX/TX queue on a given port.

            Args:
                port_id: The port that the queue resides on.
                queue_id: The ID of the queue on the port.
                size: The size to update the ring size to.
                is_rx_queue: Whether to modify an RX or TX queue. If :data:`True` an RX queue will be
                    updated, otherwise a TX queue will be updated.
                verify: If :data:`True` an additional command will be sent to check the ring size of
                    the queue in an attempt to validate that the size was changes properly.

            Raises:
                InteractiveCommandExecutionError: If `verify` is :data:`True` and there is a failure
                    when updating ring size.
            """
            queue_type = "rxq" if is_rx_queue else "txq"
            self.send_command(f"port config {port_id} {queue_type} {queue_id} ring_size {size}")
            self.setup_port_queue(port_id, queue_id, is_rx_queue)
            if verify:
                queue_info = self.send_command(f"show {queue_type} info {port_id} {queue_id}")
                if f"Number of RXDs: {size}" not in queue_info:
                    self._logger.debug(
                        f"Failed up update ring size of queue {queue_id} on port {port_id}:"
                        f"\n{queue_info}"
                    )
                    raise InteractiveCommandExecutionError(
                        f"Failed to update ring size of queue {queue_id} on port {port_id}"
                    )

    def set_promisc_on(self, port: int, on: bool, verify: bool = True):
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
