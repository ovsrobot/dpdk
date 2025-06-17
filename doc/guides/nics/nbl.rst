.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2025 Nebulamatrix Technology Co., Ltd

NBL Poll Mode Driver
====================

The NBL PMD (**librte_net_nbl**) provides poll mode driver support for
10/25/50/100/200 Gbps Nebulamatrix Series Network Adapters.


Supported NICs
--------------

The following Nebulamatrix device models are supported by the same nbl driver:

  - S1205CQ-A00CHT
  - S1105AS-A00CHT
  - S1055AS-A00CHT
  - S1052AS-A00CHT
  - S1051AS-A00CHT
  - S1045XS-A00CHT
  - S1205CQ-A00CSP
  - S1055AS-A00CSP
  - S1052AS-A00CSP


Prerequisites
-------------

- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>`
  to setup the basic DPDK environment.

- Learn about `Nebulamatrix Series NICs
  <https://www.nebula-matrix.com/main>`_.


Limitations or Known Issues
---------------------------

32-bit architectures are not supported.

Windows and BSD are not supported yet.
