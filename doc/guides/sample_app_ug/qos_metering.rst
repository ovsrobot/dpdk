..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

QoS Metering Sample Application
===============================

The QoS meter sample application demonstrates DPDK QoS marking and metering
using the Single Rate Three Color Marker (srTCM) algorithm defined in RFC 2697
and the Two Rate Three Color Marker (trTCM) algorithm defined in RFC 2698.

Overview
--------

The application uses a single thread to read packets from the RX port,
meter them, mark them with the appropriate color (green, yellow, or red),
and write them to the TX port.

A policing scheme can apply before writing packets to the TX port by dropping
or changing the packet color statically. The scheme depends on both the input
and output colors of packets processed by the meter.

Select the operation mode at compile time from the following options:

*   Simple forwarding

*   srTCM color blind

*   srTCM color aware

*   trTCM color blind

*   trTCM color aware

See RFC 2697 and RFC 2698 for details about the srTCM and trTCM configurable
parameters (CIR, CBS, and EBS for srTCM; CIR, PIR, CBS, and PBS for trTCM).

The color blind modes function equivalently to the color aware modes when
all incoming packets are green.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application source resides in the ``qos_meter`` sub-directory.

Running the Application
-----------------------

Run the application with the following command line:

.. code-block:: console

    ./dpdk-qos_meter [EAL options] -- -p PORTMASK

The application requires a single core in the EAL core mask and exactly
two ports in the application port mask. The first port in the mask handles RX;
the second port handles TX.

Refer to the *DPDK Getting Started Guide* for general information on running
applications and the Environment Abstraction Layer (EAL) options.

Explanation
-----------

Select the metering mode with these defines:

.. literalinclude:: ../../../examples/qos_meter/main.c
        :language: c
        :start-after: Traffic metering configuration. 8<
        :end-before: >8 End of traffic metering configuration.

To simplify debugging (for example, when using the traffic generator's
MAC address-based packet filtering on the RX side), the application encodes
the color in the LSB of the destination MAC address.

The application source code configures traffic meter parameters with the
following default values:

.. literalinclude:: ../../../examples/qos_meter/main.c
        :language: c
        :start-after: Traffic meter parameters are configured in the application. 8<
        :end-before: >8 End of traffic meter parameters are configured in the application.

Assuming the input traffic arrives at line rate with all packets as
64-byte Ethernet frames (46-byte IPv4 payload) colored green, the meter
marks the output traffic as shown in the following table:

.. _table_qos_metering_1:

.. table:: Output Traffic Marking

   +-------------+------------------+-------------------+----------------+
   | **Mode**    | **Green (Mpps)** | **Yellow (Mpps)** | **Red (Mpps)** |
   +=============+==================+===================+================+
   | srTCM blind | 1                | 1                 | 12.88          |
   +-------------+------------------+-------------------+----------------+
   | srTCM color | 1                | 1                 | 12.88          |
   +-------------+------------------+-------------------+----------------+
   | trTCM blind | 1                | 0.5               | 13.38          |
   +-------------+------------------+-------------------+----------------+
   | trTCM color | 1                | 0.5               | 13.38          |
   +-------------+------------------+-------------------+----------------+
   | FWD         | 14.88            | 0                 | 0              |
   +-------------+------------------+-------------------+----------------+

To configure the policing scheme, modify the static structure in the main.h
source file:

.. literalinclude:: ../../../examples/qos_meter/main.h
        :language: c
        :start-after: Policy implemented as a static structure. 8<
        :end-before: >8 End of policy implemented as a static structure.

Rows indicate the input color, columns indicate the output color, and each
table entry specifies the action for that combination.

The four available actions are:

*   GREEN: Change the packet color to green.

*   YELLOW: Change the packet color to yellow.

*   RED: Change the packet color to red.

*   DROP: Drop the packet.

In this particular case:

*   When input and output colors match, keep the same color.

*   When the color improves (output greener than input), drop the packet.
    This case cannot occur in practice, so these values go unused.

*   For all other cases, change the color to red.

.. note::

   In color blind mode, only the GREEN input row applies.
   To drop packets, set the policer_table action to DROP.
