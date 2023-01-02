..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Microsoft Corporation.

dpdk-dumpcap Application
========================

The ``dpdk-dumpcap`` tool is a Data Plane Development Kit (DPDK)
network traffic dump tool.
The interface is similar to the dumpcap tool in Wireshark.
It runs as a secondary DPDK process and lets you capture packets
that are coming into and out of a DPDK primary process.
The ``dpdk-dumpcap`` writes files in Pcapng packet format.

Without any options set, it will use DPDK to capture traffic
from the first available DPDK interface
and write the received raw packet data,
along with timestamps into a pcapng file.

If the ``-w`` option is not specified, ``dpdk-dumpcap`` writes
to a newly created file with a name chosen
based on interface name and timestamp.
If ``-w`` option is specified, then that file is used.

.. note::

   * The ``dpdk-dumpcap`` tool can only be used in conjunction with a primary
     application which has the packet capture framework initialized already.
     In DPDK, only the ``dpdk-testpmd`` is modified to initialize
     packet capture framework, other applications remain untouched.
     So, if the ``dpdk-dumpcap`` tool has to be used with any application
     other than the ``dpdk-testpmd``, user needs to explicitly modify
     that application to call packet capture framework initialization code.
     Refer ``app/test-pmd/testpmd.c`` code to see how this is done.

   * The ``dpdk-dumpcap`` tool runs as a DPDK secondary process.
     It exits when the primary application exits.


Running the Application
-----------------------

To list interfaces available for capture, use ``-D`` or ``--list-interfaces``.

To capture on multiple interfaces at once, use multiple ``-i`` flags.

To filter packets in style of *tshark*, use the ``-f`` flag. This flag
can be specified multiple times. If this flag is specified prior to ``-i``
it sets a default filter that will be used with all interfaces. If this
flag is specified after ``-i`` it defines a filter for that interface only.

To control the promiscuous mode of an interface, use the ``-p`` flag. This flag
can be specified multiple times. If this flag is specified prior to ``-i`` it
sets the default mode for all interfaces. If this flag is specified after ``-i``
it sets the mode for that interface. If you want to allow some interfaces to
remain in promiscuous mode, this must flag must be associated with an interface.


Example
-------

.. code-block:: console

   # <build_dir>/app/dpdk-dumpcap --list-interfaces
   Port    Name                                        Link        Promiscuous
   0       0000:00:03.0                                Up          Enabled
   1       0000:00:03.1                                Up          Disabled
   2       0000:00:03.2                                Down        Disabled
   3       0000:00:03.3                                Down        Disabled

   # <build_dir>/app/dpdk-dumpcap -i 0000:00:03.0 -c 6 -w /tmp/sample.pcapng
   Packets captured: 6
   Packets received/dropped on interface '0000:00:03.0' 6/0

   # <build_dir>/app/dpdk-dumpcap -f 'tcp port 80'
   Packets captured: 6
   Packets received/dropped on interface '0000:00:03.0' 10/8


Limitations
-----------

The following option of Wireshark ``dumpcap`` has a different behavior:

   * ``-s`` -- snaplen is not per interface

The following option of Wireshark ``dumpcap`` is not yet implemented:

   * ``-b|--ring-buffer`` -- more complex file management.

The following options do not make sense in the context of DPDK.

   * ``-C <byte_limit>`` -- it's a kernel thing.

   * ``-t`` -- use a thread per interface.

   * Timestamp type.

   * Link data types. Only EN10MB (Ethernet) is supported.

   * Wireless related options: ``-I|--monitor-mode`` and  ``-k <freq>``


.. note::

   * The options to ``dpdk-dumpcap`` are like the Wireshark dumpcap program
     and are not the same as ``dpdk-pdump`` and other DPDK applications.
