# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023-2024 University of New Hampshire
"""Mac address filtering test suite.

This test suite ensures proper and expected behavior of Allowlist filtering via mac
addresses on devices bound to the Poll Mode Driver. If a packet received on a device
contains a mac address not contained with its mac address pool, the packet should
be dropped. Alternatively, if a packet is received that contains a destination mac
within the devices address pool, the packet should be accepted and forwarded. This
behavior should remain consistent across all packets, namely those containing dot1q
tags or otherwise.

The following test suite assesses behaviors based on the aforementioned logic.
Additionally, testing is done within the PMD itself to ensure that the mac address
allow list is behaving as expected.
"""

from time import sleep

from scapy.layers.inet import IP  # type: ignore[import-untyped]
from scapy.layers.l2 import Dot1Q, Ether  # type: ignore[import-untyped]
from scapy.packet import Raw  # type: ignore[import-untyped]

from framework.exception import InteractiveCommandExecutionError
from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite


class TestMacFilter(TestSuite):
    """Mac address allowlist filtering test suite.

    Configure mac address filtering on a given port, and test the port's filtering behavior
    using both a given port's hardware address as well as dummy addresses. If a port accepts
    a packet that is not contained within its mac address allowlist, then a given test case
    fails. Alternatively, if a port drops a packet that is designated within its mac address
    allowlist, a given test case will fail.

    Moreover, a given port should demonstrate proper behavior when bound to the Poll Mode
    Driver. A port should not have an mac address allowlist that exceeds its designated size.
    A port's default hardware address should not be removed from its address pool, and invalid
    addresses should not be included in the allowlist. If a port abides by the above rules, the
    test case passes.
    """

    def send_packet_and_verify(
        self,
        mac_address: str,
        add_vlan: bool = False,
        should_receive: bool = True,
    ) -> None:
        """Generate, send, and verify a packet based on specified parameters.

        Test cases within this suite utilize this method to create, send, and verify
        packets based on criteria relating to the packet's destination mac address,
        vlan tag, and whether or not the packet should be received or not. Packets
        are verified using an inserted payload. If the list of received packets
        contains this payload within any of its packets, the test case passes. Each
        call with this method sends exactly one packet.

        Args:
            mac_address: The destination mac address of the packet being sent.
            add_vlan: Add a vlan tag to the packet being sent. :data:'2' if the packet
                should be received, :data:'1' if the packet should not be received but
                requires a vlan tag, and None for any other condition.
            should_receive: If :data:'True', assert whether or not the sent packet
                has been received. If :data:'False', assert that the send packet was not
                received. :data:'True' by default
        """
        if add_vlan:
            packet = Ether() / Dot1Q(vlan=2 if should_receive else 1) / IP() / Raw(load="X" * 22)
        else:
            packet = Ether() / IP() / Raw(load="X" * 22)
        packet.dst = mac_address
        received_packets = [
            packets
            for packets in self.send_packet_and_capture(packet, adjust_addresses=False)
            if hasattr(packets, "load") and "X" * 22 in str(packets.load)
        ]
        if should_receive:
            self.verify(len(received_packets) == 1, "Expected packet not received")
        else:
            self.verify(len(received_packets) == 0, "Expected packet received")

    def test_add_remove_mac_addresses(self) -> None:
        """Assess basic mac addressing filtering functionalities.

        This test cases validates for proper behavior of mac address filtering with both
        a port's default, burned-in mac address, as well as additional mac addresses
        added to the PMD. Packets should either be received or not received depending on
        the properties applied to the PMD at any given time.

        Test:
            Start TestPMD with promiscuous mode.
            Send a packet with the port's default mac address. (Should receive)
            Send a packet with fake mac address. (Should not receive)
            Add fake mac address to the PMD's address pool.
            Send a packet with the fake mac address to the PMD. (Should receive)
            Remove the fake mac address from the PMD's address pool.
            Sent a packet with the fake mac address to the PMD. (Should not receive)
        """
        testpmd = TestPmdShell(self.sut_node)
        testpmd.set_promisc(0, on=False)
        testpmd.start()
        mac_address = self._sut_port_ingress.mac_address

        # Send a packet with NIC default mac address
        self.send_packet_and_verify(mac_address=mac_address, should_receive=True)
        # Send a packet with different mac address
        fake_address = "00:00:00:00:00:01"
        self.send_packet_and_verify(mac_address=fake_address, should_receive=False)

        # Add mac address to pool and rerun tests
        testpmd.set_mac_addr(0, mac_address=fake_address, add=True)
        self.send_packet_and_verify(mac_address=fake_address, should_receive=True)
        testpmd.set_mac_addr(0, mac_address=fake_address, add=False)
        self.send_packet_and_verify(mac_address=fake_address, should_receive=False)
        testpmd.close()
        sleep(6)

    def test_invalid_address(self) -> None:
        """Assess the behavior of a NIC mac address pool while bound to the PMD.

        An assessment of a NIC's behavior when mounted to a PMD as it relates to mac addresses
        and address pooling. Devices should not be able to use invalid mac addresses, remove their
        built-in hardware address, or exceed their address pools.

        Test:
            Start TestPMD.
            Attempt to add an invalid mac address. (Should fail)
            Attempt to remove the device's hardware address with no additional addresses in the
                address pool. (Should fail)
            Add a fake mac address to the pool twice in succession. (Should not create any errors)
            Attempt to remove the device's hardware address with other addresses in the address
                pool. (Should fail)
            Determine the device's mac address pool size, and fill the pool with fake addresses.
            Attempt to add another fake mac address, overloading the address pool. (Should fail)
        """
        testpmd = TestPmdShell(self.sut_node)
        testpmd.start()
        mac_address = self._sut_port_ingress.mac_address
        try:
            testpmd.set_mac_addr(0, "00:00:00:00:00:00", add=True)
            self.verify(False, "Invalid mac address added.")
        except InteractiveCommandExecutionError:
            pass
        try:
            testpmd.set_mac_addr(0, mac_address, add=False)
            self.verify(False, "Default mac address removed.")
        except InteractiveCommandExecutionError:
            pass
        # Should be no errors adding this twice
        testpmd.set_mac_addr(0, "1" + mac_address[1:], add=True)
        testpmd.set_mac_addr(0, "1" + mac_address[1:], add=True)
        # Double check to see if default mac address can be removed
        try:
            testpmd.set_mac_addr(0, mac_address, add=False)
            self.verify(False, "Default mac address removed.")
        except InteractiveCommandExecutionError:
            pass

        for i in range(testpmd.show_port_info(0).max_mac_addresses_num - 1):
            # A0 fake address based on the index 'i'.
            fake_address = str(hex(i)[2:].zfill(12))
            # Insert ':' characters every two indexes to create a fake mac address.
            fake_address = ":".join(fake_address[x : x + 2] for x in range(0, len(fake_address), 2))
            testpmd.set_mac_addr(0, fake_address, add=True, verify=False)
        try:
            testpmd.set_mac_addr(0, "F" + mac_address[1:], add=True)
            self.verify(False, "Mac address limit exceeded.")
        except InteractiveCommandExecutionError:
            pass
        testpmd.close()
        sleep(6)

    def test_multicast_filter(self) -> None:
        """Assess basic multicast address filtering functionalities.

        Ensure that multicast filtering performs as intended when a given device is bound
        to the PMD, with and without dot1q vlan tagging.

        Test:
            Start TestPMD with promiscuous mode.
            Add a fake multicast address to the PMD's multicast address pool.
            Send a packet with the fake multicast address to the PMD. (Should receive)
            Set vlan filtering on the PMD, and add vlan ID to the PMD.
            Send a packet with the fake multicast address and vlan ID to the PMD. (Should receive)
            Send a packet with the fake multicast address and a different vlan ID to the PMD.
                (Should not receive)
            Remove the vlan tag from the PMD, and turn vlan filtering off on the PMD.
            Send a packet with the fake multicast address and no vlan tag to the PMD.
                (Should receive)
            Remove the fake multicast address from the PMDs multicast address filter.
            Send a packet with the fake multicast address to the PMD. (Should not receive)
        """
        testpmd = TestPmdShell(self.sut_node)
        testpmd.start()
        testpmd.set_promisc(0, on=False)
        multicast_address = "01:00:5E:00:00:00"
        vlan_id = 2

        testpmd.set_multicast_mac_addr(0, multi_addr=multicast_address, add=True)
        self.send_packet_and_verify(multicast_address, should_receive=True)

        # Test vlan filtering on multicast addressing.
        # Verify vlan functionality for debugging purposes.
        testpmd.vlan_filter_set_on(port=0)
        testpmd.rx_vlan_add(vlan_id, 0)
        self.send_packet_and_verify(multicast_address, should_receive=True, add_vlan=True)
        self.send_packet_and_verify(multicast_address, should_receive=False, add_vlan=True)

        # Remove vlan tag and filtering and run basic multicast addr test.
        testpmd.rx_vlan_rm(vlan_id, 0)
        testpmd.vlan_filter_set_off(port=0)
        self.send_packet_and_verify(multicast_address, should_receive=True)

        # Remove multicast filter and verify the packet was not received.
        testpmd.set_multicast_mac_addr(0, multicast_address, add=False)
        self.send_packet_and_verify(multicast_address, should_receive=False)
        testpmd.close()
        sleep(6)
