..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 Mucse IC Design Ltd.

RNP Poll Mode driver
====================

The RNP ETHDEV PMD (**librte_net_rnp**) provides poll mode ethdev
driver support for the inbuilt network device found in the **Mucse RNP**

Features
--------

- Multiple queues for TX and RX
- Receiver Side Steering (RSS)
  Receiver Side Steering (RSS) on IPv4, IPv6, IPv4-TCP/UDP/SCTP, IPv6-TCP/UDP/SCTP
  Inner RSS is only support for vxlan/nvgre
- Promiscuous mode
- Link state information
- MTU update
- MAC filtering
- Jumbo frames
- Scatter-Gather IO support
- Port hardware statistic

Prerequisites
-------------
More information can be found at `Mucse, Official Website
<https://mucse.com/productDetail>`_.
For English version you can download the below pdf.
`<https://muchuang-bucket.oss-cn-beijing.aliyuncs.com/aea70403c0de4fa58cd507632009103dMUCSE%20Product%20Manual%202023.pdf>`

Supported Chipsets and NICs
---------------------------

- MUCSE Ethernet Controller N10 Series for 10GbE or 40GbE (Dual-port)

Chip Basic Overview
-------------------
N10 isn't normal with traditional PCIe network card, The chip only have two pcie physical function.
The Chip max can support eight ports.

.. code-block:: console

  +------------------------------------------------+
  |                      OS                        |
  |                   PCIE (PF0)                   |
  |    |            |            |            |    |
  +----|------------|------------|------------|----+
       |            |            |            |
     +-|------------|------------|------------|-+
     |                Extend Mac                |
     |          VLAN/Unicast/multicast          |
     |             Promisc Mode  Ctrl           |
     |                                          |
     +-|------------|------------|------------|-+
       |            |            |            |
   +---|---+    +---|---+    +---|---+    +---|---+
   |       |    |       |    |       |    |       |
   | MAC 0 |    | MAC 1 |    | MAC 2 |    | MAC 3 |
   |       |    |       |    |       |    |       |
   +---|---+    +---|---+    +---|---+    +---|---+
       |            |            |            |
   +---|---+    +---|---+    +---|---+    +---|---+
   |       |    |       |    |       |    |       |
   | PORT 0|    | PORT 1|    | PORT 2|    | PORT 3|
   |       |    |       |    |       |    |       |
   +-------+    +-------+    +-------+    +-------+

  +------------------------------------------------+
  |                       OS                       |
  |                   PCIE (PF1)                   |
  |    |            |            |            |    |
  +----|------------|------------|------------|----+
       |            |            |            |
     +-|------------|------------|------------|-+
     |                Extend Mac                |
     |           VLAN/Unicast/multicast         |
     |             Promisc Mode  Ctrl           |
     |                                          |
     +-|------------|------------|------------|-+
       |            |            |            |
   +---|---+    +---|---+    +---|---+    +---|---+
   |       |    |       |    |       |    |       |
   | MAC 4 |    | MAC 5 |    | MAC 6 |    | MAC 7 |
   |       |    |       |    |       |    |       |
   +---|---+    +---|---+    +---|---+    +---|---+
       |            |            |            |
   +---|---+    +---|---+    +---|---+    +---|---+
   |       |    |       |    |       |    |       |
   | PORT 4|    | PORT 5|    | PORT 6|    | PORT 7|
   |       |    |       |    |       |    |       |
   +-------+    +-------+    +-------+    +-------+

Limitations or Known issues
---------------------------

BSD are not supported yet.
