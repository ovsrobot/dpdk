..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 Napatech A/S

NTNIC Poll Mode Driver
======================

The NTNIC PMD provides poll mode driver support for Napatech smartNICs.


Design
------

The NTNIC PMD is designed as a pure user-space driver, and requires no special
Napatech kernel modules.

The Napatech smartNIC presents one control PCI device (PF0). NTNIC PMD accesses
smartNIC PF0 via vfio-pci kernel driver. Access to PF0 for all purposes is
exclusive, so only one process should access it. The physical ports are located
behind PF0 as DPDK port 0 and 1. These ports can be configured with one or more
TX and RX queues each.

Virtual ports can be added by creating VFs via SR-IOV. The vfio-pci kernel
driver is bound to the VFs. The VFs implement virtio data plane only and the VF
configuration is done by NTNIC PMD through PF0. Each VF can be configured with
one or more TX and RX queue pairs. The VF’s are numbered starting from VF 4.
The number of VFs is limited by the number of queues supported by the FPGA,
and the number of queue pairs allocated for each VF. Current FPGA supports 128
queues in each TX and RX direction. A maximum of 63 VFs is supported (VF4-VF66).

As the Napatech smartNICs supports sensors and monitoring beyond what is
available in the DPDK API, the PMD includes the ntconnect socket interface.
ntconnect additionally allows Napatech to implement specific customer requests
that are not supported by the DPDK API.


Supported NICs
--------------

- NT200A02 2x100G SmartNIC

    - FPGA ID 9563 (Inline Flow Management)


Features
--------

- Multiple TX and RX queues.
- Scattered and gather for TX and RX.
- RSS based on VLAN or 5-tuple.
- RSS using different combinations of fields: L3 only, L4 only or both, and
    source only, destination only or both.
- Several RSS hash keys, one for each flow type.
- Default RSS operation with no hash key specification.
- VLAN filtering.
- RX VLAN stripping via raw decap.
- TX VLAN insertion via raw encap.
- Hairpin.
- HW checksum offload of RX and hairpin.
- Promiscuous mode on PF and VF.
- Flow API.
- Multiple process.
- Tunnel types: GTP.
- Tunnel HW offload: Packet type, inner/outer RSS, IP and UDP checksum
    verification.
- Support for multiple rte_flow groups.
- Encapsulation and decapsulation of GTP data.
- Packet modification: NAT, TTL decrement, DSCP tagging
- Traffic mirroring.
- Jumbo frame support.
- Port and queue statistics.
- RMON statistics in extended stats.
- Flow metering, including meter policy API.
- Link state information.
- CAM and TCAM based matching.
- Exact match of 140 million flows and policies.


Limitations
~~~~~~~~~~~

Kernel versions before 5.7 are not supported. Kernel version 5.7 added vfio-pci
support for creating VFs from the PF which is required for the PMD to use
vfio-pci on the PF. This support has been back-ported to older Linux
distributions and they are also supported. If vfio-pci is not required kernel
version 4.18 is supported.

Current NTNIC PMD implementation only supports one active adapter.


Configuration
-------------

Command line arguments
~~~~~~~~~~~~~~~~~~~~~~

Following standard DPDK command line arguments are used by the PMD:

    -a: Used to specifically define the NT adapter by PCI ID.
    --iova-mode: Must be set to ‘pa’ for Physical Address mode.

NTNIC specific arguments can be passed to the PMD in the PCI device parameter list::

    <application> ... -a 0000:03:00.0[{,<NTNIC specific argument>}]

The NTNIC specific argument format is::

    <object>.<attribute>=[<object-ids>:]<value>

Multiple arguments for the same device are separated by ‘,’ comma.
<object-ids> can be a single value or a range.


- ``rxqs`` parameter [int]

    Specify number of RX queues to use.

    To specify number of RX queues::

        -a <domain>:<bus>:00.0,rxqs=4,txqs=4

    By default, the value is set to 1.

- ``txqs`` parameter [int]

    Specify number of TX queues to use.

    To specify number of TX queues::

        -a <domain>:<bus>:00.0,rxqs=4,txqs=4

    By default, the value is set to 1.

- ``exception_path`` parameter [int]

    Enable exception path for unmatched packets to go through queue 0.

    To enable exception_path::

        -a <domain>:<bus>:00.0,exception_path=1

    By default, the value is set to 0.

- ``port.link_speed`` parameter [list]

    This parameter is used to set the link speed on physical ports in the format::

        port.link_speed=<port>:<link speed in Mbps>

    To set up link speeds::

        -a <domain>:<bus>:00.0,port.link_speed=0:10000,port.link_speed=1:25000

    By default, set to the maximum corresponding to the NIM bit rate.

- ``supported-fpgas`` parameter [str]

    List the supported FPGAs for a compiled NTNIC DPDK-driver.

    This parameter has two options::

        - list.
        - verbose.

    Example usages::

        -a <domain>:<bus>:00.0,supported-fpgas=list
        -a <domain>:<bus>:00.0,supported-fpgas=verbose

- ``help`` parameter [none]

    List all available NTNIC PMD parameters.


Build options
~~~~~~~~~~~~~

- ``NT_TOOLS``

    Define that enables the PMD ntconnect source code.

    Default: Enabled.

- ``NT_VF_VDPA``

    Define that enables the PMD VF VDPA source code.

    Default: Enabled.

- ``NT_RELAY_CORE``

    Define that enables the PMD replay core source code. The relay core is used
    by Napatech's vSwitch PMD profile in an OVS environment.

    Default: Disabled.


Logging and Debugging
---------------------

NTNIC supports several groups of logging that can be enabled with ``log-level``
parameter:

- ETHDEV.

    Logging info from the main PMD code. i.e. code that is related to DPDK::

        --log-level=ntnic.ethdev,8

- NTHW.

    Logging info from NTHW. i.e. code that is related to the FPGA and the Adapter::

        --log-level=ntnic.nthw,8

- vDPA.

    Logging info from vDPA. i.e. code that is related to VFIO and vDPA::

        --log-level=ntnic.vdpa,8

- FILTER.

    Logging info from filter. i.e. code that is related to the binary filter::

        --log-level=ntnic.filter,8

- FPGA.

    Logging related to FPGA::

        --log-level=ntnic.fpga,8

To enable logging on all levels use wildcard in the following way::

    --log-level=ntnic.*,8
