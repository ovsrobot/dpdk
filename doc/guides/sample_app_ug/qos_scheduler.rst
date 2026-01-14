..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

QoS Scheduler Sample Application
================================

The QoS sample application demonstrates DPDK QoS scheduling.

Overview
--------

The following figure shows the architecture of the QoS scheduler application.

.. _figure_qos_sched_app_arch:

.. figure:: img/qos_sched_app_arch.*

   QoS Scheduler Application Architecture


The application supports two runtime configurations: two or three threads
per packet flow.

The RX thread reads packets from the RX port, classifies them based on
double VLAN tags (outer and inner) and the lower byte of the IP destination
address, then enqueues them to the ring.

The worker thread dequeues packets from the ring and calls the QoS scheduler
enqueue/dequeue functions. With a separate TX core, the worker sends packets
to the TX ring. Otherwise, it sends them directly to the TX port.
The TX thread, when present, reads from the TX ring and writes packets to
the TX port.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application source resides in the ``qos_sched`` sub-directory.

.. note::

   This application supports Linux only.

.. note::

   The number of grinders defaults to 8. Modify this value by specifying
   ``RTE_SCHED_PORT_N_GRINDERS=N`` in CFLAGS, where N is the desired count.

Running the Application
-----------------------

.. note::

   The application requires at least 4 GB of huge pages per socket
   (depending on which cores are in use).

The application accepts the following command line options:

.. code-block:: console

    ./<build_dir>/examples/dpdk-qos_sched [EAL options] -- <APP PARAMS>

Mandatory application parameters:

*   ``--pfc "RX PORT, TX PORT, RX LCORE, WT LCORE, TX CORE"``: Packet flow
    configuration. Specify multiple pfc entries on the command line with
    4 or 5 items (depending on whether a TX core is defined).

Optional application parameters:

*   ``-i``: Start the application in interactive mode. This mode displays
    a command line for obtaining statistics while scheduling runs
    (see `Interactive mode`_ for details).

*   ``--mnc n``: Main core index (default: 1).

*   ``--rsz "A, B, C"``: Ring sizes:

    *   A = Size (in buffer descriptors) of each NIC RX ring read by I/O RX
        lcores (default: 128).

    *   B = Size (in elements) of each software ring that I/O RX lcores use
        to send packets to worker lcores (default: 8192).

    *   C = Size (in buffer descriptors) of each NIC TX ring written by
        worker lcores (default: 256).

*   ``--bsz "A, B, C, D"``: Burst sizes:

    *   A = I/O RX lcore read burst size from NIC RX (default: 64).

    *   B = I/O RX lcore write burst size to output software rings, worker
        lcore read burst size from input software rings, and QoS enqueue
        size (default: 64).

    *   C = QoS dequeue size (default: 63).

    *   D = Worker lcore write burst size to NIC TX (default: 64).

*   ``--msz M``: Mempool size (in mbufs) for each pfc (default: 2097152).

*   ``--rth "A, B, C"``: RX queue threshold parameters:

    *   A = RX prefetch threshold (default: 8).

    *   B = RX host threshold (default: 8).

    *   C = RX write-back threshold (default: 4).

*   ``--tth "A, B, C"``: TX queue threshold parameters:

    *   A = TX prefetch threshold (default: 36).

    *   B = TX host threshold (default: 0).

    *   C = TX write-back threshold (default: 0).

*   ``--cfg FILE``: Profile configuration file to load.

Refer to the *DPDK Getting Started Guide* for general information on running
applications and the Environment Abstraction Layer (EAL) options.

The profile configuration file defines all port/subport/pipe/traffic class/queue
parameters for the QoS scheduler.

The profile file uses the following format:

.. literalinclude:: ../../../examples/qos_sched/profile.cfg
    :start-after: Data Plane Development Kit (DPDK) Programmer's Guide

Interactive mode
~~~~~~~~~~~~~~~~

The interactive mode supports these commands:

*   Control commands:

    *   ``quit``: Exit the application.

*   General statistics:

    *   ``stats app``: Display a table of in-application statistics.

    *   ``stats port X subport Y``: For a specific subport, display the number
        of packets (and bytes) that passed through the scheduler and the
        number dropped. The table separates results by traffic class.

    *   ``stats port X subport Y pipe Z``: For a specific pipe, display the
        number of packets (and bytes) that passed through the scheduler and
        the number dropped. The table separates results by queue.

*   Average queue size:

    These commands average packet counts across a subset of queues.
    Configure two parameters before using these commands:

    *   ``qavg n X``: Set the number of calculation iterations. Higher values
        improve accuracy (default: 10).

    *   ``qavg period X``: Set the interval in microseconds between
        calculations (default: 100).

    The queue size measurement commands are:

    *   ``qavg port X subport Y``: Display average queue size per subport.

    *   ``qavg port X subport Y tc Z``: Display average queue size per subport
        for a specific traffic class.

    *   ``qavg port X subport Y pipe Z``: Display average queue size per pipe.

    *   ``qavg port X subport Y pipe Z tc A``: Display average queue size per
        pipe for a specific traffic class.

    *   ``qavg port X subport Y pipe Z tc A q B``: Display average queue size
        for a specific queue.

Example
~~~~~~~

The following command configures a single packet flow:

.. code-block:: console

    ./<build_dir>/examples/dpdk-qos_sched -l 1,5,7 -- --pfc "3,2,5,7" --cfg ./profile.cfg

This example creates one RX thread on lcore 5 reading from port 3 and a
worker thread on lcore 7 writing to port 2.

The following command configures two packet flows using different ports but
sharing the same QoS scheduler core:

.. code-block:: console

   ./<build_dir>/examples/dpdk-qos_sched -l 1,2,6,7 -- --pfc "3,2,2,6,7" --pfc "1,0,2,6,7" --cfg ./profile.cfg

The application also supports independent cores for RX, WT, and TX threads
in each packet flow configuration, providing flexibility to balance workloads.

The EAL corelist must contain only the default main core 1 plus the RX, WT,
and TX cores.

Explanation
-----------

The Port/Subport/Pipe/Traffic Class/Queue hierarchy represents entities in
a typical QoS application:

*   A subport represents a predefined group of users.

*   A pipe represents an individual user or subscriber.

*   A traffic class represents a traffic type with specific loss rate, delay,
    and jitter requirements, such as voice, video, or data transfers.

*   A queue hosts packets from one or more connections of the same type
    belonging to the same user.

Traffic flow configuration depends on the application. This application
classifies packets based on QinQ double VLAN tags and IP destination address
as shown in the following table.

.. _table_qos_scheduler_1:

.. table:: Entity Types

   +----------------+-------------------------+--------------------------------------------------+----------------------------------+
   | **Level Name** | **Siblings per Parent** | **QoS Functional Description**                   | **Selected By**                  |
   +================+=========================+==================================================+==================================+
   | Port           | -                       | Ethernet port                                    | Physical port                    |
   +----------------+-------------------------+--------------------------------------------------+----------------------------------+
   | Subport        | Config (8)              | Traffic shaped (token bucket)                    | Outer VLAN tag                   |
   +----------------+-------------------------+--------------------------------------------------+----------------------------------+
   | Pipe           | Config (4k)             | Traffic shaped (token bucket)                    | Inner VLAN tag                   |
   +----------------+-------------------------+--------------------------------------------------+----------------------------------+
   | Traffic Class  | 13                      | TCs of the same pipe services in strict priority | Destination IP address (0.0.0.X) |
   +----------------+-------------------------+--------------------------------------------------+----------------------------------+
   | Queue          | High Priority TC: 1,    | Queue of lowest priority traffic                 | Destination IP address (0.0.0.X) |
   |                | Lowest Priority TC: 4   | class (Best effort) serviced in WRR              |                                  |
   +----------------+-------------------------+--------------------------------------------------+----------------------------------+

For more information about these parameters, see the "QoS Scheduler" chapter
in the *DPDK Programmer's Guide*.
