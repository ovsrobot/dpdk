"""Implementation for TREX performance traffic generator."""

import time
from enum import Flag, auto
from typing import Any, ClassVar

from scapy.packet import Packet

from framework.config.node import NodeConfiguration
from framework.config.test_run import TrafficGeneratorConfig
from framework.context import get_ctx
from framework.exception import SSHTimeoutError
from framework.remote_session.python_shell import PythonShell
from framework.testbed_model.node import Node, create_session
from framework.testbed_model.os_session import OSSession
from framework.testbed_model.topology import Topology
from framework.testbed_model.traffic_generator.performance_traffic_generator import (
    PerformanceTrafficGenerator,
    PerformanceTrafficStats,
)


class TrexStatelessTXModes(Flag):
    """Flags indicating TREX instance's current transmission mode."""

    CONTINUOUS = auto()
    SINGLE_BURST = auto()
    MULTI_BURST = auto()


class TrexTrafficGenerator(PerformanceTrafficGenerator):
    """TREX traffic generator.

    This implementation leverages the stateless API library provided in the TREX installation.

    Attributes:
        stl_client_name: The name of the stateless client used in the stateless API.
        packet_stream_name: The name of the stateless packet stream used in the stateless API.
    """

    _os_session: OSSession
    _server_remote_session: Any

    _tg_config: TrafficGeneratorConfig
    _node_config: NodeConfiguration

    _shell: PythonShell
    _python_indentation: ClassVar[str] = " " * 4

    stl_client_name: ClassVar[str] = "client"
    packet_stream_name: ClassVar[str] = "stream"

    _streaming_mode: TrexStatelessTXModes = TrexStatelessTXModes.CONTINUOUS

    tg_cores: int = 10

    def __init__(self, tg_node: Node, config: TrafficGeneratorConfig, **kwargs) -> None:
        """Initialize the TREX server.

        Initializes needed OS sessions for the creation of the TREX server process.

        Attributes:
            tg_node: TG node the TREX instance is operating on.
            config: Traffic generator config provided for TREX instance.
        """
        super().__init__(tg_node=tg_node, config=config, **kwargs)
        self._tg_node_config = tg_node.config
        self._tg_config = config

        self._os_session = create_session(self._tg_node.config, "TREX", self._logger)
        self._server_remote_session = self._os_session.remote_session

        self._shell = PythonShell(self._tg_node, "TREX-client", privileged=True)

    def setup(self, topology: Topology):
        """Initialize and start a TREX server process."""
        super().setup(get_ctx().topology)
        # Start TREX server process.
        try:
            self._logger.info("Starting TREX server process: sending 20 second sleep.")
            server_command = [
                f"cd {self._tg_config.remote_path};",
                self._os_session._get_privileged_command(
                    f"screen -d -m ./t-rex-64 --cfg {self._tg_config.config} -c {self.tg_cores} -i"
                ),
            ]
            privileged_command = " ".join(server_command)
            self._logger.info(f"Sending: '{privileged_command}")
            self._server_remote_session.session.run(privileged_command)
            time.sleep(20)

        except SSHTimeoutError as e:
            self._logger.exception("Failed to start TREX server process.", e)

        # Start Python shell.
        self._shell.start_application()
        self._shell.send_command("import os")
        self._shell.send_command(
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
        self._shell.send_command("\n".join(imports))

        stateless_client = [
            f"{self.stl_client_name} = trex.stl.trex_stl_client.STLClient(",
            f"username='{self._tg_node_config.user}',",
            "server='127.0.0.1',",
            ")",
        ]

        self._shell.send_command(f"\n{self._python_indentation}".join(stateless_client))
        self._shell.send_command(f"{self.stl_client_name}.connect()")

    def teardown(self) -> None:
        """Teardown the TREX server and stateless implementation.

        close the TREX server process, and stop the Python shell.

        Attributes:
            ports: Associated ports used by the TREX instance.
        """
        super().teardown()
        self._os_session.send_command("pkill t-rex-64", privileged=True)
        self.close()

    def calculate_traffic_and_stats(
        self, packet: Packet, send_mpps: int, duration: float
    ) -> PerformanceTrafficStats:
        """Calculate the traffic statistics, using provided TG output.

        Takes in the statistics output provided by the stateless API implementation, and collects
        them into a performance statistics data structure.

        Attributes:
            packet: The packet being used for the performance test.
            send_mpps: the MPPS send rate.
            duration: The duration of the test.
        """
        # Convert to a dictionary.
        stats_output = eval(self._generate_traffic(packet, send_mpps, duration))

        global_output = stats_output.get("global", "ERROR - DATA NOT FOUND")

        self._logger.info(f"The global stats for the current set of params are: {global_output}")

        return PerformanceTrafficStats(
            frame_size=len(packet),
            tx_pps=global_output.get("tx_pps", "ERROR - tx_pps NOT FOUND"),
            tx_cps=global_output.get("tx_cps", "ERROR - tx_cps NOT FOUND"),
            tx_bps=global_output.get("tx_bps", "ERROR - tx_bps NOT FOUND"),
            rx_pps=global_output.get("rx_pps", "ERROR - rx_pps NOT FOUND"),
            rx_bps=global_output.get("rx_bps", "ERROR - rx_bps NOT FOUND"),
        )

    def _generate_traffic(self, packet: Packet, send_mpps: int, duration: float) -> str:
        """Generate traffic using provided packet.

        Uses the provided packet to generate traffic for the provided duration.

        Attributes:
            packet: The packet being used for the performance test.
            send_mpps: MPPS send rate.
            duration: The duration of the test being performed.

        Returns:
            a string output of statistics provided by the traffic generator.
        """
        self._create_packet_stream(packet)
        self._setup_trex_client()

        stats = self._send_traffic_and_get_stats(send_mpps, duration)

        return stats

    def _setup_trex_client(self) -> None:
        """Create trex client and connect to the server process."""
        # Prepare TREX client for next performance test.
        procedure = [
            f"{self.stl_client_name}.connect()",
            f"{self.stl_client_name}.reset(ports = [0, 1])",
            f"{self.stl_client_name}.clear_stats()",
            f"{self.stl_client_name}.add_streams({self.packet_stream_name}, ports=[0, 1])",
        ]

        for command in procedure:
            self._shell.send_command(command)

    def _create_packet_stream(self, packet: Packet) -> None:
        """Create TREX packet stream with the given packet.

        Attributes:
            packet: The packet being used for the performance test.

        """
        streaming_mode = ""
        if self._streaming_mode == TrexStatelessTXModes.CONTINUOUS:
            streaming_mode = "STLTXCont"
        elif self._streaming_mode == TrexStatelessTXModes.SINGLE_BURST:
            streaming_mode = "STLTXSingleBurst"
        elif self._streaming_mode == TrexStatelessTXModes.MULTI_BURST:
            streaming_mode = "STLTXMultiBurst"

        # Create the tx packet on the TG shell
        self._shell.send_command(f"packet={packet.command()}")

        packet_stream = [
            f"{self.packet_stream_name} = trex.stl.trex_stl_streams.STLStream(",
            f"name='Test_{len(packet)}_bytes',",
            "packet=trex.stl.trex_stl_packet_builder_scapy.STLPktBuilder(pkt=packet),",
            f"mode=trex.stl.trex_stl_streams.{streaming_mode}(percentage=100),",
            ")",
        ]
        self._shell.send_command("\n".join(packet_stream))

    def _send_traffic_and_get_stats(self, send_mpps: float, duration: float) -> str:
        """Send traffic and get TG Rx stats.

        Sends traffic from the TREX client's ports for the given duration.
        When the traffic sending duration has passed, collect the aggregate
        statistics and return TREX's global stats as a string.

        Attributes:
            send_mpps: The millions of packets per second for TREX to send from each port.
            duration: The traffic generation duration.
        """
        mpps_send_rate = f"{send_mpps}mpps"

        self._shell.send_command(f"""{self.stl_client_name}.start(ports=[0, 1],
        mult = '{mpps_send_rate}',
        duration = {duration})""")

        time.sleep(duration)

        stats = self._shell.send_command(
            f"{self.stl_client_name}.get_stats(ports=[0, 1])", skip_first_line=True
        )

        self._shell.send_command(f"{self.stl_client_name}.stop(ports=[0, 1])")

        return stats

    def close(self) -> None:
        """Overrides :meth:`.traffic_generator.TrafficGenerator.close`.

        Stops the traffic generator and sniffer shells.
        """
        self._shell.close()
