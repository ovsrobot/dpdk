..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2022 Intel Corporation.

IDPF Poll Mode Driver
======================

The [*EXPERIMENTAL*] idpf PMD (**librte_net_idpf**) provides poll mode driver support for
Intel® Infrastructure Processing Unit (Intel® IPU) E2000.


Linux Prerequisites
-------------------

- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.

- To get better performance on Intel platforms, please follow the "How to get best performance with NICs on Intel platforms"
  section of the :ref:`Getting Started Guide for Linux <linux_gsg>`.


Pre-Installation Configuration
------------------------------

Runtime Config Options
~~~~~~~~~~~~~~~~~~~~~~

- ``vport`` (default ``0``)

  The IDPF PMD supports creation of multiple vports for one PCI device, each vport
  corresponds to a single ethdev. Using the ``devargs`` parameter ``vport`` the user
  can specify the vports with specific ID to be created, for example::

    -a ca:00.0,vport=[0,2,3]

  Then idpf PMD will create 3 vports (ethdevs) for device ca:00.0.
  NOTE: If the parameter is not provided, the vport 0 will be created by default.

- ``rx_single`` (default ``0``)

  There're two queue modes supported by Intel® IPU Ethernet ES2000 Series, single queue
  mode and split queue mode for Rx queue. User can choose Rx queue mode by the ``devargs``
  parameter ``rx_single``.

    -a ca:00.0,rx_single=1

  Then idpf PMD will configure Rx queue with single queue mode. Otherwise, split queue
  mode is chosen by default.

- ``tx_single`` (default ``0``)

  There're two queue modes supported by Intel® IPU Ethernet ES2000 Series, single queue
  mode and split queue mode for Tx queue. User can choose Tx queue mode by the ``devargs``
  parameter ``tx_single``.

    -a ca:00.0,tx_single=1

  Then idpf PMD will configure Tx queue with single queue mode. Otherwise, split queue
  mode is chosen by default.


Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.


Features
--------

Vector PMD
~~~~~~~~~~

Vector path for RX and TX path are selected automatically. The paths
are chosen based on 2 conditions.

- ``CPU``
  On the X86 platform, the driver checks if the CPU supports AVX512.
  If the CPU supports AVX512 and EAL argument ``--force-max-simd-bitwidth``
  is set to 512, AVX512 paths will be chosen.

- ``Offload features``
  The supported HW offload features are described in the document idpf.ini,
  A value "P" means the offload feature is not supported by vector path.
  If any not supported features are used, idpf vector PMD is disabled and the
  scalar paths are chosen.
