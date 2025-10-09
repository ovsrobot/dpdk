.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2024 NXP

ENETC4 Poll Mode Driver
=======================

The ENETC4 NIC PMD (**librte_net_enetc**) provides poll mode driver
support for the inbuilt NIC found in the **NXP i.MX95** SoC.

More information can be found at `NXP Official Website
<https://www.nxp.com/products/processors-and-microcontrollers/arm-processors/i-mx-applications-processors/i-mx-9-processors/i-mx-95-applications-processor-family-high-performance-safety-enabled-platform-with-eiq-neutron-npu:iMX95>`_.

This section provides an overview of the NXP ENETC4
and how it is integrated into the DPDK.

Contents summary

- ENETC4 overview
- Supported ENETC4 SoCs
- PCI bus driver
- NIC driver
- Prerequisites
- Driver compilation and testing

ENETC4 Overview
---------------

ENETC4 is a PCI Integrated End Point(IEP). IEP implements
peripheral devices in an SoC such that software sees them as PCIe device.
ENETC4 is an evolution of BDR(Buffer Descriptor Ring) based networking
IPs.

This infrastructure simplifies adding support for IEP and facilitates in following:

- Device discovery and location
- Resource requirement discovery and allocation (e.g. interrupt assignment,
  device register address)
- Event reporting

Supported ENETC4 SoCs
---------------------

- i.MX95

NIC Driver (PMD)
----------------

The ENETC4 PMD is a traditional DPDK PMD that bridges the RTE framework and
ENETC4 internal drivers, supporting both Virtual Functions (VFs) and
Physical Functions (PF). Key functionality includes:

- Driver registration: The device vendor table is registered in the PCI subsystem.
- Device discovery: The RTE framework scans the PCI bus for connected devices, triggering the ENETC4 driver's probe function.
- Initialization: The probe function configures basic device registers and sets up Buffer Descriptor (BD) rings.
- Receive processing: Upon packet reception, the BD Ring status bit is set, facilitating packet processing.
- Transmission: Packet transmission precedes reception, ensuring efficient data transfer.

Prerequisites
-------------

There are three main pre-requisites for executing ENETC4 PMD on ENETC4
compatible boards:

#. **ARM 64 Tool Chain**

   For example, the `*aarch64* ARM Toolchain <https://developer.arm.com/-/media/Files/downloads/gnu/13.3.rel1/binrel/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu.tar.xz>`_.

#. **Linux Kernel**

   It can be obtained from `NXP's Github hosting <https://github.com/nxp-imx/linux-imx>`_.

The following dependencies are not part of DPDK and must be installed
separately:

- **NXP Linux LF**

  NXP Linux Factory (LF) includes support for family
  of QorIQ® ARM-Architecture-based system on chip (SoC) processors
  and corresponding boards.

  It includes the Linux board support packages (BSPs) for NXP SoCs,
  a fully operational tool chain, kernel and board specific modules.

  i.MX LF release and related information can be obtained from:  `LF  <https://www.nxp.com/design/design-center/software/embedded-software/i-mx-software/embedded-linux-for-i-mx-applications-processors:IMXLINUX>`_
  Refer section: Linux Current Release.

Driver compilation and testing
------------------------------

Follow instructions available in the document
:ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
to launch **testpmd**
