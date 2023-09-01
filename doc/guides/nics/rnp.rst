..  SPADIX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 Mucse IC Design Ltd.

RNP Poll Mode driver
====================

The RNP ETHDEV PMD (**librte_net_rnp**) provides poll mode ethdev
driver support for the inbuilt network device found in the **Mucse RNP**

Prerequisites
-------------
More information can be found at `Mucse, Official Website
<https://mucse.com/productDetail>`_.

Supported Chipsets and NICs
---------------------------

- MUCSE Ethernet Controller N10 Series for 10GbE or 40GbE (Dual-port)

Limitations or Known issues
---------------------------

Build with ICC is not supported yet.
BSD are not supported yet.

CRC stripping
~~~~~~~~~~~~~

The RNP Soc family Nic strip the CRC for every packets coming into the
host interface irrespective of the offload configuration.
When you want to disable CRC_OFFLOAD the operate will influence the rxCksum offload.

VLAN Strip/Filter
~~~~~~~~~~~~~~~~~

For VLAN strip/filter, RNP just support vlan is CVLAN(0x8100).If the outvlan type is SVLAN(0X88a8)
VLAN filter or strip will not effort for this packet.It will bypass filter to the host default queue,
whatever the other filter rule is.
