.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2021 NXP

ENETFEC Poll Mode Driver
========================

The ENETFEC NIC PMD (**librte_net_enetfec**) provides poll mode driver
support for the inbuilt NIC found in the ** NXP i.MX 8M Mini** SoC.

More information can be found at NXP Official Website
<https://www.nxp.com/products/processors-and-microcontrollers/arm-processors/i-mx-applications-processors/i-mx-8-processors/i-mx-8m-mini-arm-cortex-a53-cortex-m4-audio-voice-video:i.MX8MMINI>

ENETFEC
-------

This section provides an overview of the NXP ENETFEC and how it is
integrated into the DPDK.

Contents summary

- ENETFEC overview
- ENETFEC features
- Supported ENETFEC SoCs
- Prerequisites
- Driver compilation and testing
- Limitations

ENETFEC Overview
~~~~~~~~~~~~~~~~
The i.MX 8M Mini Media Applications Processor is built to achieve both high
performance and low power consumption. ENETFEC is a hardware programmable
packet forwarding engine to provide high performance Ethernet interface.
The diagram below shows a system level overview of ENETFEC:

   ====================================================+===============
   US   +-----------------------------------------+    | Kernel Space
	|					  |    |
	|		ENETFEC Driver		  |    |
	+-----------------------------------------+    |
			  ^   |			       |
   ENETFEC	      RXQ |   | TXQ		       |
   PMD			  |   |			       |
			  |   v			       |   +----------+
		     +-------------+		       |   | fec-uio  |
		     | net_enetfec |		       |   +----------+
		     +-------------+		       |
			  ^   |			       |
		      TXQ |   | RXQ		       |
			  |   |			       |
			  |   v			       |
    ===================================================+===============
	 +----------------------------------------+
	 |					  |	  HW
	 |	     i.MX 8M MINI EVK		  |
	 |		 +-----+		  |
	 |		 | MAC |		  |
	 +---------------+-----+------------------+
			 | PHY |
			 +-----+

ENETFEC Ethernet driver is traditional DPDK PMD driver running in the userspace.
The MAC and PHY are the hardware blocks. 'fec-uio' is the UIO driver, ENETFEC PMD
uses UIO interface to interact with kernel for PHY initialisation and for mapping
the allocated memory of register & BD in kernel with DPDK which gives access to
non-cacheable memory for BD. net_enetfec is logical Ethernet interface, created by
ENETFEC driver.

- ENETFEC driver registers the device in virtual device driver.
- RTE framework scans and will invoke the probe function of ENETFEC driver.
- The probe function will set the basic device registers and also setups BD rings.
- On packet Rx the respective BD Ring status bit is set which is then used for
  packet processing.
- Then Tx is done first followed by Rx via logical interfaces.

ENETFEC Features
~~~~~~~~~~~~~~~~~

- Basic stats
- Promiscuous
- Linux
- ARMv8

Supported ENETFEC SoCs
~~~~~~~~~~~~~~~~~~~~~~

- i.MX 8M Mini

Prerequisites
~~~~~~~~~~~~~

There are three main pre-requisites for executing ENETFEC PMD on a i.MX 8M Mini
compatible board:

1. **ARM 64 Tool Chain**

   For example, the `*aarch64* Linaro Toolchain <https://releases.linaro.org/components/toolchain/binaries/7.4-2019.02/aarch64-linux-gnu/gcc-linaro-7.4.1-2019.02-x86_64_aarch64-linux-gnu.tar.xz>`_.

2. **Linux Kernel**

  It can be obtained from `NXP's Github hosting <https://source.codeaurora.org/external/qoriq/qoriq-components/linux>`_.

3. **Rootfile system**

   Any *aarch64* supporting filesystem can be used. For example,
   Ubuntu 18.04 LTS (Bionic) or 20.04 LTS(Focal) userland which can be obtained
   from `here <http://cdimage.ubuntu.com/ubuntu-base/releases/18.04/release/ubuntu-base-18.04.1-base-arm64.tar.gz>`_.

4. The Ethernet device will be registered as virtual device, so ENETFEC has dependency on
   **rte_bus_vdev** library and it is mandatory to use `--vdev` with value `net_enetfec` to
   run DPDK application.

Driver compilation and testing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow instructions available in the document
:ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
to launch **dpdk-testpmd**

Limitations
~~~~~~~~~~~

- Multi queue is not supported.
- Link status is down always.
- Single Ethernet interface.
