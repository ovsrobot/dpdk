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
behind PF0 as DPDK port 0 and 1.


Supported NICs
--------------

- NT200A02 2x100G SmartNIC

    - FPGA ID 9563 (Inline Flow Management)


Features
--------

- Link state information.


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

- FPGA.

    Logging related to FPGA::

        --log-level=ntnic.fpga,8

To enable logging on all levels use wildcard in the following way::

    --log-level=ntnic.*,8
