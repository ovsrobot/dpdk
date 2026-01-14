..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Intel Corporation.

VMDq Forwarding Sample Application
==================================

The VMDq Forwarding sample application demonstrates packet processing using the DPDK.
The application performs L2 forwarding using Intel VMDq (Virtual Machine Device Queues)
to divide incoming traffic into queues. The traffic splitting is performed in hardware
by the VMDq feature of Intel 82599 and X710/XL710 Ethernet Controllers.

Overview
--------

This sample application can serve as a starting point for developing DPDK applications
that use VMDq for traffic partitioning.

About VMDq Technology
~~~~~~~~~~~~~~~~~~~~~

VMDq is a silicon-level technology designed to improve network I/O performance in
virtualized environments. In traditional virtualized systems, the Virtual Machine Monitor
(VMM) must sort incoming packets and route them to the correct virtual machine, consuming
significant CPU cycles. VMDq offloads this packet sorting to the network controller hardware,
freeing CPU resources for application workloads.

When packets arrive at a VMDq-enabled network adapter, a Layer 2 classifier in the controller
sorts packets based on MAC addresses and VLAN tags, then places each packet in the receive
queue assigned to the appropriate destination. This hardware-based pre-sorting reduces the
overhead of software-based virtual switches.

How VMDq Filtering Works
~~~~~~~~~~~~~~~~~~~~~~~~

VMDq filters split incoming packets into different pools, each with its own set of RX queues,
based on the MAC address and VLAN ID within the VLAN tag of the packet.

All traffic is read from a single incoming port and output on another port without modification.
For the Intel 82599 NIC, traffic is split into 128 queues on input. Each application thread
reads from multiple queues. When running with 8 threads (using the ``-c FF`` option), each
thread receives and forwards packets from 16 queues.

Supported Configurations
~~~~~~~~~~~~~~~~~~~~~~~~

The sample application supports the following configurations:

- **Intel 82599 10 Gigabit Ethernet Controller**: 32 pools with 4 queues each (default),
  or 16 pools with 2 queues each.

- **Intel X710/XL710 Ethernet Controllers**: Multiple configurations of VMDq pools
  with 4 or 8 queues each. The number of queues per VMDq pool can be changed by setting
  ``RTE_LIBRTE_I40E_QUEUE_NUM_PER_VM`` in ``config/rte_config.h``.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``vmdq`` sub-directory.

Running the Application
-----------------------

To run the example in a Linux environment:

.. code-block:: console

    ./<build_dir>/examples/dpdk-vmdq -l 0-3 -- -p 0x3 --nb-pools 16

Command-Line Options
~~~~~~~~~~~~~~~~~~~~

The following application-specific options are available after the EAL parameters:

``-p PORTMASK``
    Hexadecimal bitmask of ports to configure.

``--nb-pools NP``
    Number of VMDq pools. Valid values are 8, 16, or 32.

``--enable-rss``
    Enable Receive Side Scaling. RSS is disabled by default.

Example:

.. code-block:: console

    ./<build_dir>/examples/dpdk-vmdq [EAL options] -- -p 0x3 --nb-pools 32 --enable-rss

Refer to the *DPDK Getting Started Guide* for general information on running applications
and the Environment Abstraction Layer (EAL) options.

Explanation
-----------

The following sections explain the code structure.

Initialization
~~~~~~~~~~~~~~

The EAL, driver, and PCI configuration is performed similarly to the L2 Forwarding sample
application, as is the creation of the mbuf pool. See :doc:`l2_forward_real_virtual` for details.

This example application differs in the configuration of the NIC port for RX. The VMDq
hardware feature is configured at port initialization time by setting appropriate values
in the ``rte_eth_conf`` structure passed to the ``rte_eth_dev_configure()`` API.

Initially, the application provides a default structure for VMDq configuration:

.. literalinclude:: ../../../examples/vmdq/main.c
    :language: c
    :start-after: Default structure for VMDq. 8<
    :end-before: >8 End of Empty vdmq configuration structure.

The ``get_eth_conf()`` function fills in the ``rte_eth_conf`` structure with appropriate
values based on the global ``vlan_tags`` array. Each VLAN ID can be allocated to multiple
pools of queues.

For destination MAC addresses, each VMDq pool is assigned a MAC address using the format
``52:54:00:12:<port_id>:<pool_id>``. For example, VMDq pool 2 on port 1 uses the MAC address
``52:54:00:12:01:02``.

.. literalinclude:: ../../../examples/vmdq/main.c
    :language: c
    :start-after: vlan_tags 8<
    :end-before: >8 End of vlan_tags.

.. literalinclude:: ../../../examples/vmdq/main.c
    :language: c
    :start-after: Pool mac address template. 8<
    :end-before: >8 End of mac addr template.

.. literalinclude:: ../../../examples/vmdq/main.c
    :language: c
    :start-after: Building correct configuration for vdmq. 8<
    :end-before: >8 End of get_eth_conf.

After the network port is initialized with VMDq values, the port's RX and TX hardware rings
are initialized similarly to the L2 Forwarding sample application.
See :doc:`l2_forward_real_virtual` for more information.

Statistics Display
~~~~~~~~~~~~~~~~~~

When running in a Linux environment, the application can display statistics showing the
number of packets read from each RX queue. The application uses a signal handler for the
SIGHUP signal that prints packet counts in grid form, with each row representing a single
pool and each column representing a queue number within that pool.

To generate the statistics output:

.. code-block:: console

    sudo killall -HUP dpdk-vmdq

.. note::

    The statistics output appears on the terminal where the application is running,
    not on the terminal from which the HUP signal was sent.
