..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 Mucse IC Design Ltd.

RNP Poll Mode driver
==========================

The RNP ETHDEV PMD (**librte_net_rnp**) provides poll mode ethdev
driver support for the inbuilt network device found in the **Mucse RNP**

Prerequisites
-------------
More information can be found at `Mucse, Official Website
<https://mucse.com/productDetail>`_.

Supported RNP SoCs
------------------------

- N10

Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.

#. Running testpmd:

   Follow instructions available in the document
   :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
   to run testpmd.

Limitations or Known issues
-----------
Build with ICC is not supported yet.
CRC stripping
~~~~~~~~~~~~
The RNP SoC family NICs strip the CRC for every packets coming into the
host interface irrespective of the offload configuration.
When You Want To Disable CRC_OFFLOAD The Feature Will Influence The RxCksum Offload
VLAN Strip
~~~~~~~~~~~~~~~~~~
For VLAN Strip RNP Just Support CVLAN(0x8100) Type If The Vlan Type Is SVLAN(0X88a8)
VLAN Filter Or Strip Will Not Effert For This Packet It Will Bypass To The Host.
