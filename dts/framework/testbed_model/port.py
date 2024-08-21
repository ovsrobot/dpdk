# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 University of New Hampshire
# Copyright(c) 2023 PANTHEON.tech s.r.o.

"""NIC port model.

Basic port information, such as location (the port are identified by their PCI address on a node),
drivers and address.
"""


from dataclasses import dataclass

from framework.config import PortConfig


@dataclass(slots=True)
class Port:
    """Physical port on a node.

    The ports are identified using a unique, user-defined name/identifier.
    Each port is serviced by a driver, which may be different for the operating system (`os_driver`)
    and for DPDK (`os_driver_for_dpdk`). For some devices, they are the same, e.g.: ``mlx5_core``.

    Attributes:
        node_name: Node the port exists on.
        name: User-defined unique identifier of the port.
        pci: The pci address assigned to the port.
        os_driver: The operating system driver name when the operating system controls the port,
            e.g.: ``i40e``.
        os_driver_for_dpdk: The operating system driver name for use with DPDK, e.g.: ``vfio-pci``.
        mac_address: The MAC address of the port.
        logical_name: The logical name of the port. Must be discovered.
    """

    node: str
    name: str
    pci: str
    os_driver: str
    os_driver_for_dpdk: str
    mac_address: str = ""
    logical_name: str = ""

    def __init__(self, node_name: str, config: PortConfig):
        """Initialize the port from `node_name` and `config`.

        Args:
            node_name: The name of the port's node.
            config: The test run configuration of the port.
        """
        self.node = node_name
        self.name = config.name
        self.pci = config.pci
        self.os_driver = config.os_driver
        self.os_driver_for_dpdk = config.os_driver_for_dpdk


@dataclass(slots=True, frozen=True)
class PortLink:
    """The physical, cabled connection between the ports.

    Attributes:
        sut_port: The port on the SUT node connected to `tg_port`.
        tg_port: The port on the TG node connected to `sut_port`.
    """

    sut_port: Port
    tg_port: Port
