# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2025 University of New Hampshire

"""Virtio forwarding test suite.

Verify vhost/virtio pvp and loopback topology functionalities.
"""

import re

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from framework.params.testpmd import SimpleForwardingModes
from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite, func_test
from framework.testbed_model.capability import requires
from framework.testbed_model.linux_session import LinuxSession
from framework.testbed_model.topology import TopologyType
from framework.testbed_model.virtual_device import VirtualDevice


@requires(topology_type=TopologyType.two_links)
class TestVirtioFwd(TestSuite):
    """Virtio forwarding test suite."""

    @func_test
    def virtio_server(self) -> None:
        """Test virtio server packet transmission.

        Steps:
            * Launch a testpmd session with a vhost-user virtual device (client side).
            * Launch a testpmd session with a virtio-user virtual device (server side).
            * Set the forwarding mode to mac in both sessions.
            * Start packet forwarding on vhost session.
            * Send a burst of packets from the virtio session.
            * Stop packet forwarding on vhost session and collect Rx packet stats.

        Verify:
            * Vhost session receives packets from virtio session.
        """
        with (
            TestPmdShell(
                prefix="vhost",
                no_pci=True,
                memory_channels=4,
                vdevs=[VirtualDevice("eth_vhost0,iface=/tmp/vhost-net,client=1")],
            ) as vhost,
            TestPmdShell(
                prefix="virtio",
                no_pci=True,
                memory_channels=4,
                vdevs=[
                    VirtualDevice(
                        "net_virtio_user0,mac=00:01:02:03:04:05,path=/tmp/vhost-net,server=1"
                    )
                ],
            ) as virtio,
        ):
            vhost.set_forward_mode(SimpleForwardingModes.mac)
            virtio.set_forward_mode(SimpleForwardingModes.mac)

            vhost.start()
            virtio.start_tx_first(burst_num=32)

            forwarding_stats = vhost.stop()

            match_rx = re.search(r"RX-packets:\s*(\d+)", forwarding_stats)
            match_tx = re.search(r"TX-packets:\s*(\d+)", forwarding_stats)
            rx_packets = int(match_rx[1]) if match_rx else 0
            tx_packets = int(match_tx[1]) if match_tx else 0

            self.verify(
                rx_packets != 0 and tx_packets != 0,
                "Vhost session failed to receive packets from virtio session.",
            )

    @func_test
    def virtio_server_reconnect(self) -> None:
        """Test virtio server reconnection.

        Steps:
            * Launch a testpmd session with a vhost-user virtual device (client side).
            * Launch a testpmd session with a virtio-user virtual device (server side).
            * Close the virtio session and relaunch it.
            * Start packet forwarding on vhost session.
            * Send a burst of packets from the virtio session.
            * Stop packet forwarding on vhost session and collect Rx packet stats.

        Verify:
            * Vhost session receives packets from relaunched virtio session.
        """
        with TestPmdShell(
            prefix="vhost",
            no_pci=True,
            memory_channels=4,
            vdevs=[VirtualDevice("eth_vhost0,iface=/tmp/vhost-net,client=1")],
        ) as vhost:
            with TestPmdShell(
                prefix="virtio",
                no_pci=True,
                memory_channels=4,
                vdevs=[
                    VirtualDevice(
                        "net_virtio_user0,mac=00:01:02:03:04:05,path=/tmp/vhost-net,server=1"
                    )
                ],
            ) as virtio:
                pass
            # end session and reconnect
            with TestPmdShell(
                prefix="virtio",
                no_pci=True,
                memory_channels=4,
                vdevs=[
                    VirtualDevice(
                        "net_virtio_user0,mac=00:01:02:03:04:05,path=/tmp/vhost-net,server=1"
                    )
                ],
            ) as virtio:
                virtio.set_forward_mode(SimpleForwardingModes.mac)
                vhost.set_forward_mode(SimpleForwardingModes.mac)

                vhost.start()
                virtio.start_tx_first(burst_num=32)

                forwarding_stats = vhost.stop()

                match_rx = re.search(r"RX-packets:\s*(\d+)", forwarding_stats)
                match_tx = re.search(r"TX-packets:\s*(\d+)", forwarding_stats)
                rx_packets = int(match_rx[1]) if match_rx else 0
                tx_packets = int(match_tx[1]) if match_tx else 0

                self.verify(
                    rx_packets != 0 and tx_packets != 0,
                    "Vhost session failed to receive packets from virtio session.",
                )

    @func_test
    def pvp_loop(self) -> None:
        """Test vhost/virtio physical-virtual-physical loop topology.

        Steps:
            * Launch testpmd session with a physical NIC and virtio-user vdev
                connected to a vhost-net socket.
            * Configure the tap interface that is created with IP address and
                set link state to UP.
            * Launch second testpmd session with af_packet vdev connected to
                the tap interface.
            * Start packet forwarding on both testpmd sessions.
            * Send 100 packets to the physical interface from external tester.
            * Capture packets on the same physical interface.

        Verify:
            * Physical interface receives all 100 sent packets.
        """
        self.sut_node = self._ctx.sut_node
        if not isinstance(self._ctx.sut_node.main_session, LinuxSession):
            self.verify(False, "Must be running on a Linux environment.")
        with TestPmdShell(
            prefix="virtio",
            vdevs=[VirtualDevice("virtio_user0,path=/dev/vhost-net,queues=1,queue_size=1024")],
        ) as virtio:
            self.sut_node.main_session.send_command("ip link set dev tap0 up", privileged=True)
            with TestPmdShell(
                prefix="vhost", no_pci=True, vdevs=[VirtualDevice("net_af_packet0,iface=tap0")]
            ) as vhost:
                virtio.set_forward_mode(SimpleForwardingModes.mac)
                vhost.set_forward_mode(SimpleForwardingModes.mac)
                vhost.start()
                virtio.start()

                packet = Ether() / IP()
                packets = [packet] * 100
                captured_packets = self.send_packets_and_capture(packets)

                self.verify(
                    len(captured_packets) >= 100, "Sent packets not received on physical interface."
                )
