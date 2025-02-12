# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022 University of New Hampshire
# Copyright(c) 2023 PANTHEON.tech s.r.o.

"""Traffic generator node.

A traffic generator (TG) generates traffic that's sent towards the SUT node.
A TG node is where the TG runs.
"""

from collections.abc import Iterable

from scapy.packet import Packet

from framework.config.node import TGNodeConfiguration
from framework.config.test_run import TestRunConfiguration
from framework.testbed_model.traffic_generator.capturing_traffic_generator import (
    PacketFilteringConfig,
)

from .node import Node
from .port import Port
from .traffic_generator import CapturingTrafficGenerator, create_traffic_generator


class TGNode(Node):
    """The traffic generator node.

    The TG node extends :class:`Node` with TG specific features:

        * Traffic generator initialization,
        * The sending of traffic and receiving packets,
        * The sending of traffic without receiving packets.

    Not all traffic generators are capable of capturing traffic, which is why there
    must be a way to send traffic without that.

    Attributes:
        config: The traffic generator node configuration.
        traffic_generator: The traffic generator running on the node.
    """

    config: TGNodeConfiguration
    traffic_generator: CapturingTrafficGenerator

    def __init__(self, node_config: TGNodeConfiguration):
        """Extend the constructor with TG node specifics.

        Initialize the traffic generator on the TG node.

        Args:
            node_config: The TG node's test run configuration.
        """
        super().__init__(node_config)
        self._logger.info(f"Created node: {self.name}")

    def set_up_test_run(self, test_run_config: TestRunConfiguration, ports: Iterable[Port]) -> None:
        """Extend the test run setup with the setup of the traffic generator.

        Args:
            test_run_config: A test run configuration according to which
                the setup steps will be taken.
            ports: The ports to set up for the test run.
        """
        super().set_up_test_run(test_run_config, ports)
        self.main_session.bring_up_link(ports)
        self.traffic_generator = create_traffic_generator(self, self.config.traffic_generator)

    def tear_down_test_run(self, ports: Iterable[Port]) -> None:
        """Extend the test run teardown with the teardown of the traffic generator.

        Args:
            ports: The ports to tear down for the test run.
        """
        super().tear_down_test_run(ports)
        self.traffic_generator.close()

    def send_packets_and_capture(
        self,
        packets: list[Packet],
        send_port: Port,
        receive_port: Port,
        filter_config: PacketFilteringConfig = PacketFilteringConfig(),
        duration: float = 1,
    ) -> list[Packet]:
        """Send `packets`, return received traffic.

        Send `packets` on `send_port` and then return all traffic captured
        on `receive_port` for the given duration. Also record the captured traffic
        in a pcap file.

        Args:
            packets: The packets to send.
            send_port: The egress port on the TG node.
            receive_port: The ingress port in the TG node.
            filter_config: The filter to use when capturing packets.
            duration: Capture traffic for this amount of time after sending `packet`.

        Returns:
             A list of received packets. May be empty if no packets are captured.
        """
        return self.traffic_generator.send_packets_and_capture(
            packets,
            send_port,
            receive_port,
            filter_config,
            duration,
        )

    def send_packets(self, packets: list[Packet], port: Port):
        """Send packets without capturing resulting received packets.

        Args:
            packets: Packets to send.
            port: Port to send the packets on.
        """
        self.traffic_generator.send_packets(packets, port)

    def close(self) -> None:
        """Free all resources used by the node.

        This extends the superclass method with TG cleanup.
        """
        super().close()
