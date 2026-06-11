..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2017 Intel Corporation

..  bbdev_app:

Loop-back Sample Application using Baseband Device (bbdev)
==========================================================

The baseband sample application is a simple example of packet processing using
the Data Plane Development Kit (DPDK) for baseband workloads using Wireless
Device abstraction library.

Overview
--------

The Baseband device sample application performs a loop-back operation using a
baseband device capable of performing encoding and decoding operations.
A packet is received on an Ethernet port, enqueued for downlink baseband
operation, dequeued from the downlink baseband device, enqueued for uplink
baseband operation, dequeued from the baseband device, compared with the
expected output, and then transmitted back to the Ethernet port.

The MAC header is preserved in the packet throughout the loop-back operation.

Limitations
-----------

* Only one baseband device and one Ethernet port can be used.

Compiling the Application
-------------------------

DPDK needs to be built with ``baseband_turbo_sw`` PMD enabled along
with ``FLEXRAN SDK`` Libraries. Refer to *SW Turbo Poll Mode Driver*
documentation for more details.

To compile the sample application, see :doc:`compiling`.


Running the Application
-----------------------

The application accepts a number of command line options:

.. code-block:: console

    $ ./<build_dir>/examples/dpdk-bbdev [EAL options] -- [-e ENCODING_CORES] /
    [-d DECODING_CORES] [-p ETH_PORT_ID] [-b BBDEV_ID]

Where:

``-e ENCODING_CORES``
   Hexadecimal bitmask specifying lcores for encoding operations (default: 0x2).

``-d DECODING_CORES``
   Hexadecimal bitmask specifying lcores for decoding operations (default: 0x4).

``-p ETH_PORT_ID``
   Ethernet port ID (default: 0).

``-b BBDEV_ID``
   Baseband device ID (default: 0).

The application requires that baseband devices are capable of performing
the specified baseband operations at initialization time. Hardware baseband
devices must be bound to a DPDK driver, or software baseband devices (virtual
BBdev) must be created using the ``--vdev`` option.

To run the application in a Linux environment with the turbo_sw baseband device,
using one encoding lcore and one decoding lcore:

.. code-block:: console

    $ ./<build_dir>/examples/dpdk-bbdev --vdev='baseband_turbo_sw' -a <NIC0PCIADDR> \
    -l 3,4,5 --numa-mem=2,2 --file-prefix=bbdev -- -e 0x10 -d 0x20

Where ``NIC0PCIADDR`` is the PCI address of the Ethernet port.

This command creates one virtual BBdev device (``baseband_turbo_sw``) and
allows access to the specified Ethernet port. Three cores are allocated:

- Core 3: Main lcore, prints statistics to screen
- Core 4: Encoding lcore, performs Rx and Turbo Encode operations
- Core 5: Decoding lcore, performs Turbo Decode, validation, and Tx operations


Refer to the *DPDK Getting Started Guide* for general information on running
applications and the Environment Abstraction Layer (EAL) options.

Using Packet Generator with baseband device sample application
--------------------------------------------------------------

To allow the bbdev sample app to do the loopback, an influx of traffic is required.
This can be done using DPDK Pktgen to generate traffic on Ethernet ports.
Executing the command below will generate traffic on the allowed Ethernet
ports.

.. code-block:: console

    $ ./pktgen-3.4.0/app/x86_64-native-linux-gcc/pktgen -l 1,2 \
    --numa-mem=1,1 --file-prefix=pg -a <NIC1PCIADDR> -- -m 1.0 -P

where:

* ``-l CORELIST``: A list of cores on which the app should run
* ``--numa-mem``: Memory to allocate on specific sockets (use comma separated values)
* ``--file-prefix``: Prefix for hugepage filenames
* ``-a <NIC1PCIADDR>``: Add a PCI device in allow list. The argument format is <[domain:]bus:devid.func>.
* ``-m <string>``: Matrix for mapping ports to logical cores.
* ``-P``: PROMISCUOUS mode


Refer to *The Pktgen Application* documentation for general information on running
Pktgen with DPDK applications.
