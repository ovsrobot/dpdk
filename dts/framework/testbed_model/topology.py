# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 PANTHEON.tech s.r.o.

"""Testbed topology representation.

A topology of a testbed captures what links are available between the testbed's nodes.
The link information then implies what type of topology is available.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable

from framework.config import PortConfig

from .port import Port


class TopologyType(IntEnum):
    """Supported topology types."""

    #: A topology with no Traffic Generator.
    no_link = 0
    #: A topology with one physical link between the SUT node and the TG node.
    one_link = 1
    #: A topology with two physical links between the Sut node and the TG node.
    two_links = 2


class Topology:
    """Testbed topology.

    The topology contains ports processed into ingress and egress ports.
    If there are no ports on a node, dummy ports (ports with no actual values) are stored.
    If there is only one link available, the ports of this link are stored
    as both ingress and egress ports.

    The dummy ports shouldn't be used. It's up to :class:`~framework.runner.DTSRunner`
    to ensure no test case or suite requiring actual links is executed
    when the topology prohibits it and up to the developers to make sure that test cases
    not requiring any links don't use any ports. Otherwise, the underlying methods
    using the ports will fail.

    Attributes:
        type: The type of the topology.
        tg_port_egress: The egress port of the TG node.
        sut_port_ingress: The ingress port of the SUT node.
        sut_port_egress: The egress port of the SUT node.
        tg_port_ingress: The ingress port of the TG node.
    """

    type: TopologyType
    tg_port_egress: Port
    sut_port_ingress: Port
    sut_port_egress: Port
    tg_port_ingress: Port

    def __init__(self, sut_ports: Iterable[Port], tg_ports: Iterable[Port]):
        """Create the topology from `sut_ports` and `tg_ports`.

        Args:
            sut_ports: The SUT node's ports.
            tg_ports: The TG node's ports.
        """
        port_links = []
        for sut_port in sut_ports:
            for tg_port in tg_ports:
                if (sut_port.identifier, sut_port.peer) == (
                    tg_port.peer,
                    tg_port.identifier,
                ):
                    port_links.append(PortLink(sut_port=sut_port, tg_port=tg_port))

        self.type = TopologyType(len(port_links))
        dummy_port = Port(PortConfig("", "", "", "", "", ""))
        self.tg_port_egress = dummy_port
        self.sut_port_ingress = dummy_port
        self.sut_port_egress = dummy_port
        self.tg_port_ingress = dummy_port
        if self.type > TopologyType.no_link:
            self.tg_port_egress = port_links[0].tg_port
            self.sut_port_ingress = port_links[0].sut_port
            self.sut_port_egress = self.sut_port_ingress
            self.tg_port_ingress = self.tg_port_egress
        if self.type > TopologyType.one_link:
            self.sut_port_egress = port_links[1].sut_port
            self.tg_port_ingress = port_links[1].tg_port


@dataclass(slots=True, frozen=True)
class PortLink:
    """The physical, cabled connection between the ports.

    Attributes:
        sut_port: The port on the SUT node connected to `tg_port`.
        tg_port: The port on the TG node connected to `sut_port`.
    """

    sut_port: Port
    tg_port: Port
