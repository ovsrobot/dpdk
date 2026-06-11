..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2015 Intel Corporation.

Packet Ordering Application
============================

The Packet Ordering sample application demonstrates packet reordering
functionality and its impact on stream processing.
It stresses the library with different configurations for performance.

Overview
--------

The application uses at least three CPU cores:

* The RX core (main core) receives traffic from the NIC ports and feeds worker
  cores with traffic through SW queues.

* Worker cores perform lightweight processing on each packet.
  For configurations with more than one port enabled, it swaps the destination
  port of the packet.

* The TX core receives traffic from worker cores through software queues,
  inserts out-of-order packets into reorder buffer, extracts ordered packets
  from the reorder buffer, and sends them to the NIC ports for transmission.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``packet_ordering`` sub-directory.

Running the Application
-----------------------

Refer to *DPDK Getting Started Guide* for general information on running applications
and the Environment Abstraction Layer (EAL) options.

Explanation
-----------

Application Command Line
~~~~~~~~~~~~~~~~~~~~~~~~

The application execution command line is:

.. code-block:: console

    ./<build_dir>/examples/dpdk-packet_ordering [EAL options] -- -p PORTMASK /
    [--disable-reorder] [--insight-worker]

The ``-l`` EAL corelist option must contain at least 3 CPU cores.
The first CPU core in the corelist is assigned to the RX core (main core),
the last to the TX core, and the remaining cores to worker cores.

The ``PORTMASK`` parameter must specify either 1 port or an even number of ports.
When setting more than 1 port, traffic is forwarded in pairs.
For example, if 4 ports are enabled, traffic flows between port 0 and port 1,
and between port 2 and port 3 (forming port pairs [0,1] and [2,3]).

The ``--disable-reorder`` option disables packet reordering, which allows
evaluation of the performance impact of reordering.

The ``--insight-worker`` long option enables outputting packet statistics for each worker thread.
