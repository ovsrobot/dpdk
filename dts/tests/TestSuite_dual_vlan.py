# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 University of New Hampshire

"""Dual VLAN functionality testing suite.

The main objective of this test suite is to ensure that standard VLAN functions such as stripping
and filtering both still carry out their expected behavior in the presence of a packet which
contains two VLAN headers. These functions should carry out said behavior not just in isolation,
but also when other VLAN functions are configured on the same port. In addition to this, the
priority attributes of VLAN headers should be unchanged in the case of multiple VLAN headers
existing on a single packet, and a packet with only a single VLAN header should be able to have one
additional VLAN inserted into it.
"""
from enum import Flag, auto
from typing import ClassVar

from scapy.layers.l2 import Dot1Q, Ether  # type: ignore[import-untyped]
from scapy.packet import Packet, Raw  # type: ignore[import-untyped]

from framework.params.testpmd import SimpleForwardingModes
from framework.remote_session.testpmd_shell import TestPmdShell
from framework.test_suite import TestSuite


class TestDualVlan(TestSuite):
    """DPDK Dual VLAN test suite.

    This suite tests the behavior of VLAN functions and properties in the presence of two VLAN
    headers. All VLAN functions which are tested in this suite are specified using the inner class
    :class:`TestCaseOptions` and should have cases for configuring them in
    :meth:`configure_testpmd` as well as cases for testing their behavior in
    :meth:`verify_vlan_functions`. Every combination of VLAN functions being enabled should be
    tested. Additionally, attributes of VLAN headers, such as priority, are tested to ensure they
    are not modified in the case of two VLAN headers.
    """

    class TestCaseOptions(Flag):
        """Flag for specifying which VLAN functions to configure."""

        #:
        VLAN_STRIP = auto()
        #:
        VLAN_FILTER_INNER = auto()
        #:
        VLAN_FILTER_OUTER = auto()

    #: ID to set on inner VLAN tags.
    inner_vlan_tag: ClassVar[int] = 2
    #: ID to set on outer VLAN tags.
    outer_vlan_tag: ClassVar[int] = 1
    #: ID to use when inserting VLAN tags.
    vlan_insert_tag: ClassVar[int] = 3
    #:
    rx_port: ClassVar[int] = 0
    #:
    tx_port: ClassVar[int] = 1

    def is_relevant_packet(self, pkt: Packet) -> bool:
        """Check if a packet was sent by functions in this suite.

        All functions in this test suite send packets with a payload that is packed with 20 "X"
        characters. This method, therefore, can determine if the packet was sent by this test suite
        by just checking to see if this payload exists on the received packet.

        Args:
            pkt: Packet to check for relevancy.

        Returns:
            :data:`True` if the packet contains the expected payload, :data:`False` otherwise.
        """
        return hasattr(pkt, "load") and "X" * 20 in str(pkt.load)

    def pkt_payload_contains_layers(self, pkt: Packet, *expected_layers: Dot1Q) -> bool:
        """Verify that the payload of the packet matches `expected_layers`.

        The layers in the payload of `pkt` must match the type and the user-defined fields of the
        layers in `expected_layers` in order.

        Args:
            pkt: Packet to check the payload of.
            *expected_layers: Layers expected to be in the payload of `pkt`.

        Returns:
            :data:`True` if the payload of `pkt` matches the layers in `expected_layers` in order,
            :data:`False` otherwise.
        """
        current_pkt_layer = pkt.payload
        ret = True
        for layer in expected_layers:
            ret &= isinstance(current_pkt_layer, type(layer))
            if not ret:
                break
            for field, val in layer.fields.items():
                ret &= (
                    hasattr(current_pkt_layer, field) and getattr(current_pkt_layer, field) == val
                )
            current_pkt_layer = current_pkt_layer.payload
        return ret

    def verify_vlan_functions(self, send_packet: Packet, options: TestCaseOptions) -> None:
        """Send packet and verify the received packet has the expected structure.

        Expected structure is defined by `options` according to the following table:
        +----------------------------------------------+-----------------------+
        |                  Configure setting           |       Result          |
        +=======+=======+========+============+========+=======+=======+=======+
        | Outer | Inner |  Vlan  |   Vlan     | Vlan   | Pass/ | Outer | Inner |
        | vlan  | vlan  |  strip |   filter   | insert | Drop  | vlan  | vlan  |
        +-------+-------+--------+------------+--------+-------+-------+-------+
        |  0x1  |  0x2  |   no   |     no     |   no   | pass  |  0x1  |  0x2  |
        +-------+-------+--------+------------+--------+-------+-------+-------+
        |  0x1  |  0x2  |  yes   |     no     |   no   | pass  |  no   |  0x2  |
        +-------+-------+--------+------------+--------+-------+-------+-------+
        |  0x1  |  0x2  |   no   |  yes,0x1   |   no   | pass  |  0x1  |  0x2  |
        +-------+-------+--------+------------+--------+-------+-------+-------+
        |  0x1  |  0x2  |   no   |  yes,0x2   |   no   | pass  |  0x1  |  0x2  |
        +-------+-------+--------+------------+--------+-------+-------+-------+
        |  0x1  |  0x2  |   no   | yes,0x1,0x2|   no   | pass  |  0x1  |  0x2  |
        +-------+-------+--------+------------+--------+-------+-------+-------+
        |  0x1  |  0x2  |  yes   |  yes,0x1   |   no   | pass  |  no   |  0x2  |
        +-------+-------+--------+------------+--------+-------+-------+-------+
        |  0x1  |  0x2  |  yes   |  yes,0x2   |   no   | pass  |  no   |  0x2  |
        +-------+-------+--------+------------+--------+-------+-------+-------+
        |  0x1  |  0x2  |  yes   | yes,0x1,0x2|   no   | pass  |  no   |  0x2  |
        +-------+-------+--------+------------+--------+-------+-------+-------+

        Args:
            send_packet: Packet to send for testing.
            options: Flag which defines the currents configured settings in testpmd.
        """
        recv = self.send_packet_and_capture(send_packet)
        recv = list(filter(self.is_relevant_packet, recv))
        expected_layers: list[Packet] = []

        if self.TestCaseOptions.VLAN_STRIP not in options:
            expected_layers.append(Dot1Q(vlan=self.outer_vlan_tag))
        expected_layers.append(Dot1Q(vlan=self.inner_vlan_tag))

        self.verify(
            len(recv) > 0,
            f"Expected to receive packet with the payload {expected_layers} but got nothing.",
        )

        for pkt in recv:
            self.verify(
                self.pkt_payload_contains_layers(pkt, *expected_layers),
                f"Received packet ({pkt.summary()}) did not match the expected sequence of layers "
                f"{expected_layers} with options {options}.",
            )

    def configure_testpmd(self, shell: TestPmdShell, options: TestCaseOptions, add: bool) -> None:
        """Configure VLAN functions in testpmd based on `options`.

        Args:
            shell: Testpmd session to configure the settings on. Expected to already be running
                with all ports stopped before being passed into this function.
            options: Settings to modify in `shell`.
            add: If :data:`True`, turn the settings in `options` on, otherwise turn them off.
        """
        if (
            self.TestCaseOptions.VLAN_FILTER_INNER in options
            or self.TestCaseOptions.VLAN_FILTER_OUTER in options
        ):
            if add:
                # If we are adding a filter, filtering has to be enabled first
                shell.vlan_filter_set(self.rx_port, True)

            if self.TestCaseOptions.VLAN_FILTER_INNER in options:
                shell.rx_vlan(self.inner_vlan_tag, self.rx_port, add)
            if self.TestCaseOptions.VLAN_FILTER_OUTER in options:
                shell.rx_vlan(self.outer_vlan_tag, self.rx_port, add)

            if not add:
                # If we are removing filters then we need to remove the filters before we can
                # disable filtering.
                shell.vlan_filter_set(self.rx_port, False)
        if self.TestCaseOptions.VLAN_STRIP in options:
            shell.vlan_strip_set(self.rx_port, add)

    def test_insert_second_vlan(self) -> None:
        """Test that a packet with a single VLAN can have an additional one inserted into it."""
        with TestPmdShell(self.sut_node, forward_mode=SimpleForwardingModes.mac) as testpmd:
            testpmd.port_stop_all()
            testpmd.tx_vlan_set(self.tx_port, self.vlan_insert_tag)
            testpmd.port_start_all()
            testpmd.start()
            recv = self.send_packet_and_capture(
                Ether() / Dot1Q(vlan=self.outer_vlan_tag) / Raw("X" * 20)
            )
            self.verify(len(recv) > 0, "Did not receive any packets when testing VLAN insertion.")
            self.verify(
                any(
                    self.is_relevant_packet(p)
                    and self.pkt_payload_contains_layers(
                        p, *[Dot1Q(vlan=self.vlan_insert_tag), Dot1Q(vlan=self.outer_vlan_tag)]
                    )
                    for p in recv
                ),
                "Packet was unable to insert a second VLAN tag.",
            )

    def test_all_vlan_functions(self) -> None:
        """Test that all combinations of :class:`TestCaseOptions` behave as expected.

        To test this, the base case is tested first, ensuring that a packet with two VLANs is
        unchanged without the VLAN modification functions enabled. Then the same Testpmd shell is
        modified to enable all necessary VLAN functions, followed by verification that the
        functions work as expected, and finally the functions are disabled to allow for a clean
        environment for the next test.
        """
        send_pakt = (
            Ether()
            / Dot1Q(vlan=self.outer_vlan_tag)
            / Dot1Q(vlan=self.inner_vlan_tag)
            / Raw("X" * 20)
        )
        with TestPmdShell(self.sut_node, forward_mode=SimpleForwardingModes.mac) as testpmd:
            testpmd.start()
            recv = self.send_packet_and_capture(send_pakt)
            self.verify(len(recv) > 0, "Unmodified packet was not received.")
            self.verify(
                any(
                    self.is_relevant_packet(p)
                    and self.pkt_payload_contains_layers(
                        p, *[Dot1Q(vlan=self.outer_vlan_tag), Dot1Q(vlan=self.inner_vlan_tag)]
                    )
                    for p in recv
                ),
                "Packet was modified without any VLAN functions applied.",
            )
            testpmd.stop()
            testpmd.port_stop_all()
            for i in range(2 ** len(self.TestCaseOptions)):
                options = self.TestCaseOptions(i)
                self.configure_testpmd(testpmd, options, True)
                testpmd.port_start_all()
                testpmd.start()
                self.verify_vlan_functions(send_pakt, options)
                testpmd.stop()
                testpmd.port_stop_all()
                self.configure_testpmd(testpmd, options, False)

    def test_maintains_priority(self) -> None:
        """Test that priorities of multiple VLAN tags are preserved by the PMD."""
        pakt = (
            Ether()
            / Dot1Q(vlan=self.outer_vlan_tag, prio=1)
            / Dot1Q(vlan=self.inner_vlan_tag, prio=2)
            / Raw("X" * 20)
        )
        with TestPmdShell(self.sut_node, forward_mode=SimpleForwardingModes.mac) as testpmd:
            testpmd.start()
            recv = self.send_packet_and_capture(pakt)
            self.verify(len(recv) > 0, "Did not receive any packets when testing VLAN priority.")
            self.verify(
                any(
                    self.is_relevant_packet(p)
                    and self.pkt_payload_contains_layers(
                        p,
                        *[
                            Dot1Q(vlan=self.outer_vlan_tag, prio=1),
                            Dot1Q(vlan=self.inner_vlan_tag, prio=2),
                        ],
                    )
                    for p in recv
                ),
                "Vlan headers did not maintain their priorities.",
            )
