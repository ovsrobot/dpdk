"""Implementation for TREX performance traffic generator."""

import time
from dataclasses import dataclass
from enum import Flag, auto
from typing import Callable, ClassVar

from invoke.runners import Promise
from scapy.packet import Packet

from framework.config.node import NodeConfiguration
from framework.config.test_run import TrafficGeneratorConfig
from framework.exception import SSHTimeoutError
from framework.remote_session.python_shell import PythonShell
from framework.remote_session.ssh_session import SSHSession
from framework.testbed_model.linux_session import LinuxSession
from framework.testbed_model.node import Node, create_session
from framework.testbed_model.traffic_generator.performance_traffic_generator import (
    PerformanceTrafficGenerator,
    PerformanceTrafficStats,
)


@dataclass
class TrexPerPortStats:
    """Performance statistics on a per port basis.

    Attributes:
        opackets: Number of packets sent.
        obytes: Number of egress bytes sent.
        tx_bps: Maximum bits per second transmitted.
        tx_pps: Number of transmitted packets sent.
    """

    opackets: float
    obytes: float
    tx_bps: float
    tx_pps: float


@dataclass
class TrexPerformanceStats(PerformanceTrafficStats):
    """Data structure to store performance statistics for a given test run.

    Attributes:
        packet: The packet that was sent in the test run.
        frame_size: The total length of the frame. (L2 downward)
        tx_expected_bps: The expected bits per second on a given NIC.
        tx_expected_cps: ...
        tx_expected_pps: The expected packets per second of a given NIC.
        tx_pps: The recorded maximum packets per second of the tested NIC.
        tx_cps: The recorded maximum cps of the tested NIC
        tx_bps: The recorded maximum bits per second of the tested NIC.
        obytes: Total bytes output during test run.
        port_stats: A list of :class:`TrexPerPortStats` provided by TREX.
    """

    packet: Packet
    frame_size: int

    tx_expected_bps: float
    tx_expected_cps: float
    tx_expected_pps: float

    tx_pps: float
    tx_cps: float
    tx_bps: float

    obytes: float

    port_stats: list[TrexPerPortStats] | None


class TrexStatelessTXModes(Flag):
    """Flags indicating TREX instance's current trasmission mode."""

    CONTINUOUS = auto()
    SINGLE_BURST = auto()
    MULTI_BURST = auto()


class TrexTrafficGenerator(PythonShell, PerformanceTrafficGenerator):
    """TREX traffic generator.

    This implementation leverages the stateless API library provided in the TREX installation.

    Attributes:
        stl_client_name: The name of the stateless client used in the stateless API.
        packet_stream_name: The name of the stateless packet stream used in the stateless API.
        timeout_duration: Internal timeout for connection to the TREX server.
    """

    _os_session: LinuxSession
    _server_remote_session: SSHSession
    _trex_server_process: Promise

    _tg_config: TrafficGeneratorConfig
    _node_config: NodeConfiguration

    _python_indentation: ClassVar[str] = " " * 4

    stl_client_name: ClassVar[str] = "client"
    packet_stream_name: ClassVar[str] = "stream"

    _streaming_mode: TrexStatelessTXModes = TrexStatelessTXModes.CONTINUOUS

    timeout_duration: int

    def __init__(
        self, tg_node: Node, config: TrafficGeneratorConfig, timeout_duration: int = 5, **kwargs
    ) -> None:
        """Initialize the TREX server.

        Initializes needed OS sessions for the creation of the TREX server process.

        Attributes:
            tg_node: TG node the TREX instance is operating on.
            config: Traffic generator config provided for TREX instance.
            timeout_duration: Internal timeout for connection to the TREX server.
        """
        super().__init__(node=tg_node, config=config, tg_node=tg_node, **kwargs)
        self._node_config = tg_node.config
        self._tg_config = config
        self.timeout_duration = timeout_duration

        # Create TREX server session.
        self._tg_node._other_sessions.append(
            create_session(self._tg_node.config, "TREX Server.", self._logger)
        )
        self._os_session = self._tg_node._other_sessions[0]
        self._server_remote_session = self._os_session.remote_session

    def setup(self, ports):
        """Initialize and start a TREX server process.

        Binds TG ports to vfio-pci and starts the trex process.

        Attributes:
            ports: Related ports utilized in TG instance.
        """
        super().setup(ports)
        # Start TREX server process.
        try:
            self._logger.info("Starting TREX server process: sending 45 second sleep.")
            privileged_command = self._os_session._get_privileged_command(
                f"""
                    cd /opt/v3.03/; {self._tg_config.remote_path}/t-rex-64
                     --cfg {self._tg_config.config} -i
                """
            )
            self._server_remote_session = self._server_remote_session._send_async_command(
                privileged_command, timeout=None, env=None
            )
            time.sleep(45)
        except SSHTimeoutError as e:
            self._logger.exception("Failed to start TREX server process.", e)

        # Start Python shell.
        self.start_application()
        self.send_command("import os")
        # Parent directory: /opt/v3.03/automation/trex_control_plane/interactive
        self.send_command(
            f"os.chdir('{self._tg_config.remote_path}/automation/trex_control_plane/interactive')"
        )

        # Import stateless API components.
        imports = [
            "import trex",
            "import trex.stl",
            "import trex.stl.trex_stl_client",
            "import trex.stl.trex_stl_streams",
            "import trex.stl.trex_stl_packet_builder_scapy",
            "from scapy.layers.l2 import Ether",
            "from scapy.layers.inet import IP",
            "from scapy.packet import Raw",
        ]
        self.send_command("\n".join(imports))

        stateless_client = [
            f"{self.stl_client_name} = trex.stl.trex_stl_client.STLClient(",
            f"username='{self._node_config.user}',",
            "server='127.0.0.1',",
            f"sync_timeout={self.timeout_duration}",
            ")",
        ]
        self.send_command(f"\n{self._python_indentation}".join(stateless_client))
        self.send_command(f"{self.stl_client_name}.connect()")

    def teardown(self, ports):
        """Teardown the TREX server and stateless implementation.

        close the TREX server process, and stop the Python shell.

        Attributes:
            ports: Associated ports used by the TREX instance.
        """
        super().teardown(ports)
        self.send_command(f"{self.stl_client_name}.disconnect()")
        self.close()
        self._trex_server_process.join()

    def _calculate_traffic_stats(
        self, packet: Packet, duration: float, callback: Callable[[Packet, float], str]
    ) -> PerformanceTrafficStats:
        """Calculate the traffic statistics, using provided TG output.

        Takes in the statistics output provided by the stateless API implementation, and collects
        them into a performance statistics data structure.

        Attributes:
            packet: The packet being used for the performance test.
            duration: The duration of the test.
            callback: The callback function used to generate the traffic.
        """
        # Convert to a dictionary.
        stats_output = eval(callback(packet, duration))
        return TrexPerformanceStats(
            len(packet),
            packet,
            stats_output.get("tx_expected_bps", "ERROR - DATA NOT FOUND"),
            stats_output.get("tx_expected_cps", "ERROR - DATA NOT FOUND"),
            stats_output.get("tx_expected_pps", "ERROR - DATA NOT FOUND"),
            stats_output.get("tx_pps", "ERROR - DATA NOT FOUND"),
            stats_output.get("tx_cps", "ERROR - DATA NOT FOUND"),
            stats_output.get("tx_bps", "ERROR - DATA NOT FOUND"),
            stats_output.get("obytes", "ERROR - DATA NOT FOUND"),
            None,
        )

    def set_streaming_mode(self, streaming_mode: TrexStatelessTXModes) -> None:
        """Set the streaming mode of the TREX instance."""
        # Streaming modes are mutually exclusive.
        self._streaming_mode = self._streaming_mode & streaming_mode

    def _generate_traffic(self, packet: Packet, duration: float) -> str:
        """Generate traffic using provided packet.

        Uses the provided packet to generate traffic for the provided duration.

        Attributes:
            packet: The packet being used for the performance test.
            duration: The duration of the test being performed.

        Returns:
            a string output of statistics provided by the traffic generator.
        """
        """Implementation for :method:`generate_traffic_and_stats`."""
        streaming_mode = ""
        if self._streaming_mode == TrexStatelessTXModes.CONTINUOUS:
            streaming_mode = "STLTXCont"
        elif self._streaming_mode == TrexStatelessTXModes.SINGLE_BURST:
            streaming_mode = "STLTXSingleBurst"
        elif self._streaming_mode == TrexStatelessTXModes.MULTI_BURST:
            streaming_mode = "STLTXMultiBurst"

        packet_stream = [
            f"{self.packet_stream_name} = trex.stl.trex_stl_streams.STLStream(",
            f"name='Test_{len(packet)}_bytes',",
            f"packet=trex.stl.trex_stl_packet_builder_scapy.STLPktBuilder(pkt={packet.command()}),",
            f"mode=trex.stl.trex_stl_streams.{streaming_mode}(),",
            ")",
        ]
        self.send_command("\n".join(packet_stream))

        # Prepare TREX console for next performance test.
        procedure = [
            f"{self.stl_client_name}.connect()",
            f"{self.stl_client_name}.reset(ports = [0, 1])",
            f"{self.stl_client_name}.add_streams({self.packet_stream_name}, ports=[0, 1])",
            f"{self.stl_client_name}.clear_stats()",
            ")",
        ]
        self.send_command("\n".join(procedure))

        start_test = [
            f"{self.stl_client_name}.start(ports=[0, 1], duration={duration})",
            f"{self.stl_client_name}.wait_on_traffic(ports=[0, 1])",
        ]
        self.send_command("\n".join(start_test))
        import time

        time.sleep(duration + 1)

        # Gather statistics output for parsing.
        return self.send_command(
            f"{self.stl_client_name}.get_stats(ports=[0, 1])", skip_first_line=True
        )
