from pathlib import PurePath

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
    _path_to_app: PurePath

    def __init__(
        self,
        interactive_session: SSHClient,
        logger: DTSLOG,
        path_to_app: PurePath,
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
        self._path_to_app = path_to_app
        self._start_application()

    def _start_application(self) -> None:
        """Starts a new interactive application based on _path_to_app.

        This method is often overridden by subclasses as their process for
        starting may look different.
        """
        self.send_command_no_output(f"{self._path_to_app}")

    def send_command_no_output(self, command: str) -> None:
        """Send command to channel without recording output.

        This method will not verify any input or output, it will simply assume the
        command succeeded. This method will also consume all output in the buffer
        after executing the command.
        """
        self._logger.info(
            f"Sending command {command.strip()} and not collecting output"
        )
        self._stdin.write(f"{command}\n")
        self._stdin.flush()
        self.empty_stdout_buffer()

    def empty_stdout_buffer(self) -> None:
        """Removes all data from the stdout buffer.

        Because of the way paramiko handles read buffers, there is no way to effectively
        remove data from, or "flush", read buffers. This method essentially moves our
        offset on the buffer to the end and thus "removes" the data from the buffer.
        Timeouts are thrown on read operations of paramiko pipes based on whether data
        had been received before timeout so we assume that if we reach the timeout then
        we are at the end of the buffer.
        """
        self._ssh_channel.settimeout(0.5)
        try:
            for line in self._stdout:
                pass
        except TimeoutError:
            pass
        self._ssh_channel.settimeout(self._timeout)  # reset timeout

    def send_command_get_output(self, command: str, prompt: str) -> str:
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
        self._stdin.write(f"{command}\n")
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
