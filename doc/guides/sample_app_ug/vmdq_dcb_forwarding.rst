..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

VMDq and DCB Forwarding Sample Application
==========================================

The VMDq and DCB Forwarding sample application demonstrates packet processing using the DPDK.
The application performs L2 forwarding using Intel VMDq (Virtual Machine Device Queues) combined
with DCB (Data Center Bridging) to divide incoming traffic into queues. The traffic splitting
is performed in hardware by the VMDq and DCB features of Intel 82599 and X710/XL710
Ethernet Controllers.

Overview
--------

This sample application can serve as a starting point for developing DPDK applications
that use VMDq and DCB for traffic partitioning.

About VMDq and DCB Technology
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

VMDq is a silicon-level technology that offloads network I/O packet sorting from the
Virtual Machine Monitor (VMM) to the network controller hardware. This reduces CPU
overhead in virtualized environments by performing Layer 2 classification in hardware.

DCB (Data Center Bridging) extends VMDq by adding Quality of Service (QoS) support.
DCB uses the VLAN user priority field (also called Priority Code Point or PCP) to
classify packets into different traffic classes, enabling bandwidth allocation and
priority-based queuing.

How VMDq and DCB Filtering Works
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The VMDq and DCB filters work together on MAC and VLAN traffic to divide packets into
input queues:

1. **VMDq filtering**: Splits traffic into 16 or 32 groups based on the destination
   MAC address and VLAN ID.

2. **DCB classification**: Places each packet into one of the queues within its VMDq
   group based on the VLAN user priority field.

All traffic is read from a single incoming port (port 0) and output on port 1 without
modification. For the Intel 82599 NIC, traffic is split into 128 queues on input.
Each application thread reads from multiple queues. When running with 8 threads
(using the ``-c FF`` option), each thread receives and forwards packets from 16 queues.

:numref:`figure_vmdq_dcb_example` illustrates the packet flow through the application.

.. _figure_vmdq_dcb_example:

.. figure:: img/vmdq_dcb_example.*

   Packet Flow Through the VMDq and DCB Sample Application

Supported Configurations
~~~~~~~~~~~~~~~~~~~~~~~~

The sample application supports the following configurations:

- **Intel 82599 10 Gigabit Ethernet Controller**: 32 pools with 4 queues each (default),
  or 16 pools with 8 queues each.

- **Intel X710/XL710 Ethernet Controllers**: Multiple configurations of VMDq pools
  with 4 or 8 queues each. For simplicity, this sample supports only 16 or 32 pools.
  The number of queues per VMDq pool can be changed by setting
  ``RTE_LIBRTE_I40E_QUEUE_NUM_PER_VM`` in ``config/rte_config.h``.

.. note::

    Since VMDq queues are used for virtual machine management, this application works
    correctly when VT-d is disabled in the BIOS or Linux kernel (``intel_iommu=off``).

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``vmdq_dcb`` sub-directory.

Running the Application
-----------------------

To run the example in a Linux environment:

.. code-block:: console

    ./<build_dir>/examples/dpdk-vmdq_dcb -l 0-3 -- -p 0x3 --nb-pools 32 --nb-tcs 4

Command-Line Options
~~~~~~~~~~~~~~~~~~~~

The following application-specific options are available after the EAL parameters:

``-p PORTMASK``
    Hexadecimal bitmask of ports to configure.

``--nb-pools NP``
    Number of VMDq pools. Valid values are 16 or 32.

``--nb-tcs TC``
    Number of traffic classes. Valid values are 4 or 8.

``--enable-rss``
    Enable Receive Side Scaling. RSS is disabled by default.

Example:

.. code-block:: console

    ./<build_dir>/examples/dpdk-vmdq_dcb [EAL options] -- -p 0x3 --nb-pools 32 --nb-tcs 4 --enable-rss

Refer to the *DPDK Getting Started Guide* for general information on running applications
and the Environment Abstraction Layer (EAL) options.

Explanation
-----------

The following sections explain the code structure.

Initialization
~~~~~~~~~~~~~~

The EAL, driver, and PCI configuration is performed similarly to the L2 Forwarding sample
application, as is the creation of the mbuf pool. See :doc:`l2_forward_real_virtual` for details.

This example application differs in the configuration of the NIC port for RX. The VMDq and
DCB hardware features are configured at port initialization time by setting appropriate values
in the ``rte_eth_conf`` structure passed to the ``rte_eth_dev_configure()`` API.

Initially, the application provides a default structure for VMDq and DCB configuration:

.. literalinclude:: ../../../examples/vmdq_dcb/main.c
    :language: c
    :start-after: Empty vmdq+dcb configuration structure. Filled in programmatically. 8<
    :end-before: >8 End of empty vmdq+dcb configuration structure.

Traffic Class and Queue Assignment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``get_eth_conf()`` function fills in the ``rte_eth_conf`` structure with appropriate
values based on the global ``vlan_tags`` array. The function divides user priority values
among individual queues (traffic classes) within each pool.

For Intel 82599 NICs:

- With 32 pools: User priority fields are allocated 2 per queue.
- With 16 pools: Each of the 8 user priority fields is allocated to its own queue.

For Intel X710/XL710 NICs:

- With 4 traffic classes and 8 queues per pool: User priority fields are allocated
  2 per traffic class, with 2 queues mapped to each traffic class. RSS determines
  the destination queue within each traffic class.

For VLAN IDs, each ID can be allocated to multiple pools of queues, so the ``pools``
parameter in the ``rte_eth_vmdq_dcb_conf`` structure is specified as a bitmask.

.. literalinclude:: ../../../examples/vmdq_dcb/main.c
    :language: c
    :start-after: Dividing up the possible user priority values. 8<
    :end-before: >8 End of dividing up the possible user priority values.

MAC Address Assignment
^^^^^^^^^^^^^^^^^^^^^^

Each VMDq pool is assigned a MAC address using the format ``52:54:00:12:<port_id>:<pool_id>``.
For example, VMDq pool 2 on port 1 uses the MAC address ``52:54:00:12:01:02``.

.. literalinclude:: ../../../examples/vmdq_dcb/main.c
    :language: c
    :start-after: Set mac for each pool. 8<
    :end-before: >8 End of set mac for each pool.
    :dedent: 1

After the network port is initialized with VMDq and DCB values, the port's RX and TX
hardware rings are initialized similarly to the L2 Forwarding sample application.
See :doc:`l2_forward_real_virtual` for more information.

Statistics Display
~~~~~~~~~~~~~~~~~~

When running in a Linux environment, the application can display statistics showing the
number of packets read from each RX queue. The application uses a signal handler for the
SIGHUP signal that prints packet counts in grid form, with each row representing a single
pool and each column representing a queue number within that pool.

To generate the statistics output:

.. code-block:: console

    sudo killall -HUP dpdk-vmdq_dcb

.. note::

    The statistics output appears on the terminal where the application is running,
    not on the terminal from which the HUP signal was sent.
