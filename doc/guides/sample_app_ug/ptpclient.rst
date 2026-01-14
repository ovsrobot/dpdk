..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2015 Intel Corporation.

PTP Client Sample Application
=============================

Overview
--------

The PTP (Precision Time Protocol) client sample application demonstrates
the DPDK IEEE1588 API for synchronizing time with a PTP time transmitter.
The application synchronizes the NIC clock and optionally the Linux system clock.

.. note::

   PTP is a time synchronization protocol and cannot serve as a
   timestamping mechanism within DPDK.

For an explanation of the protocol, see
`Precision Time Protocol
<https://en.wikipedia.org/wiki/Precision_Time_Protocol>`_.

This application uses the IEEE 1588g-2022 alternative terminology
("time transmitter" and "time receiver" instead of "master" and "slave").
For the official standard, see the
`IEEE 1588 Standard
<https://standards.ieee.org/ieee/1588/6825/>`_.


Limitations
~~~~~~~~~~~

The PTP sample application provides a simple reference implementation of
a PTP client using the DPDK IEEE1588 API.
To keep the application simple, it makes the following assumptions:

* The first discovered time transmitter becomes the session's primary transmitter.
* The application supports only L2 PTP packets.
* The application supports only PTP v2 protocol.
* The application implements only the time receiver clock.


How the Application Works
~~~~~~~~~~~~~~~~~~~~~~~~~

.. _figure_ptpclient_highlevel:

.. figure:: img/ptpclient.*

   PTP Synchronization Protocol

The PTP synchronization in the sample application works as follows:

* The time transmitter sends a *Sync* message; the time receiver saves the arrival time as T2.
* The time transmitter sends a *Follow_Up* message containing T1 (the *Sync* transmission time).
* The time receiver sends a *Delay_Req* message to the time transmitter and records T3.
* The time transmitter replies with a *Delay_Resp* message containing T4 (when it received the *Delay_Req*).

The time receiver calculates the adjustment as:

   adj = -[(T2-T1)-(T4 - T3)]/2

If you specify the command line parameter ``-T 1``, the application also
synchronizes the Linux kernel clock with the PTP PHC clock.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application source resides in the ``ptpclient`` sub-directory.


Running the Application
-----------------------

To run the example in a Linux environment:

.. code-block:: console

    ./<build_dir>/examples/dpdk-ptpclient -l 1 -- -p 0x1 -T 0

Refer to the *DPDK Getting Started Guide* for general information on running
applications and the Environment Abstraction Layer (EAL) options.

* ``-p portmask``: Hexadecimal portmask.
* ``-T 0``: Update only the PTP time receiver clock.
* ``-T 1``: Update the PTP time receiver clock and synchronize the Linux kernel clock to it.


Explanation
-----------

The following sections explain the main components of the code.

All DPDK library functions used in the sample code have the ``rte_`` prefix.
The *DPDK API Documentation* explains these functions in detail.


The Main Function
~~~~~~~~~~~~~~~~~

The ``main()`` function initializes the application and launches execution
threads for each lcore.

The first task initializes the Environment Abstraction Layer (EAL). The
``rte_eal_init()`` function receives the ``argc`` and ``argv`` arguments
and returns the number of parsed arguments:

.. literalinclude:: ../../../examples/ptpclient/ptpclient.c
    :language: c
    :start-after: Initialize the Environment Abstraction Layer (EAL). 8<
    :end-before: >8 End of initialization of EAL.
    :dedent: 1

Next, the application parses application-specific arguments:

.. literalinclude:: ../../../examples/ptpclient/ptpclient.c
    :language: c
    :start-after: Parse specific arguments. 8<
    :end-before: >8 End of parsing specific arguments.
    :dedent: 1

The ``main()`` function also allocates a mempool to hold the mbufs (Message Buffers)
that the application uses:

.. literalinclude:: ../../../examples/ptpclient/ptpclient.c
    :language: c
    :start-after: Creates a new mempool in memory to hold the mbufs. 8<
    :end-before:  >8 End of a new mempool in memory to hold the mbufs.
    :dedent: 1

Mbufs provide the packet buffer structure that DPDK uses. The "Mbuf Library"
section of the *DPDK Programmer's Guide* explains them in detail.

The ``main()`` function also initializes all ports using the user-defined
``port_init()`` function with the user-provided portmask:

.. literalinclude:: ../../../examples/ptpclient/ptpclient.c
    :language: c
    :start-after: Initialize all ports. 8<
    :end-before: >8 End of initialization of all ports.
    :dedent: 1


After initialization completes, the application launches a function on an lcore.
In this example, ``main()`` calls ``lcore_main()`` on a single lcore.

.. code-block:: c

	lcore_main();

The next section explains the ``lcore_main()`` function.


The Lcores Main
~~~~~~~~~~~~~~~

As shown above, the ``main()`` function calls an application function on the
available lcores.

The application performs its main work within the loop:

.. literalinclude:: ../../../examples/ptpclient/ptpclient.c
    :language: c
    :start-after: Read packet from RX queues. 8<
    :end-before: >8 End of read packets from RX queues.
    :dedent: 2

The loop receives packets one by one on the RX ports and, when required,
transmits PTP response packets on the TX ports.

If the mbuf offload flags indicate a PTP packet, the code parses the packet
to determine its type:

.. literalinclude:: ../../../examples/ptpclient/ptpclient.c
    :language: c
    :start-after: Packet is parsed to determine which type. 8<
    :end-before: >8 End of packet is parsed to determine which type.
    :dedent: 3


The code frees all packets explicitly using ``rte_pktmbuf_free()``.

Press ``Ctrl-C`` to interrupt the forwarding loop and close the application.


PTP parsing
~~~~~~~~~~~

The ``parse_ptp_frames()`` function processes PTP packets, implementing the
PTP IEEE1588 L2 time receiver functionality.

.. literalinclude:: ../../../examples/ptpclient/ptpclient.c
    :language: c
    :start-after: Parse ptp frames. 8<
    :end-before:  >8 End of function processes PTP packets.

A minimal PTP time receiver client must parse three packet types on the RX path:

* *Sync* packet
* *Follow_Up* packet
* *Delay_Resp* packet

When the code parses the *Follow_Up* packet, it also creates and sends a
*Delay_Req* packet. When it parses the *Delay_Resp* packet and all
conditions are met, it adjusts the PTP time receiver clock.
