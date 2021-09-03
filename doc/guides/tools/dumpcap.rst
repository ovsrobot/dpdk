..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Microsoft Corporation.

.. _dumpcap_tool:

dpdk-dumpcap Application
========================

The ``dpdk-dumpcap`` tool is a Data Plane Development Kit (DPDK)
network traffic dump tool.  The interface is similar to  the dumpcap tool in Wireshark.
It runs as a secondary DPDK process and lets you capture packets that are
coming into and out of a DPDK primary process.
The ``dpdk-dumpcap`` writes files in Pcapng packet format using
capture file format is pcapng.

Without any options set it will use DPDK to capture traffic from the first
available DPDK interface and write the received raw packet data, along
with timestamps into a pcapng file.

If the ``-w`` option is not specified, ``dpdk-dumpcap`` writes to a newly
create file with a name chosen based on interface name and timestamp.
If ``-w`` option is specified, then that file is used.

   .. Note::
      * The ``dpdk-dumpcap`` tool can only be used in conjunction with a primary
        application which has the packet capture framework initialized already.
        In dpdk, only the ``testpmd`` is modified to initialize packet capture
        framework, other applications remain untouched. So, if the ``dpdk-dumpcap``
        tool has to be used with any application other than the testpmd, user
        needs to explicitly modify that application to call packet capture
        framework initialization code. Refer ``app/test-pmd/testpmd.c``
        code to see how this is done.

      * The ``dpdk-dumpcap`` tool runs as a DPDK secondary process. It exits when
        the primary application exits.


Running the Application
-----------------------

To list interfaces available for capture use ``--list-interfaces``.

To capture on multiple interfaces at once, use multiple ``-I`` flags.

Example
-------

.. code-block:: console

   # ./<build_dir>/app/dpdk-dumpcap --list-interfaces
   0. 000:00:03.0
   1. 000:00:03.1

   # ./<build_dir>/app/dpdk-dumpcap -I 0000:00:03.0 -c 6 -w /tmp/sample.pcapng
   Packets captured: 6
   Packets received/dropped on interface '0000:00:03.0' 6/0


Limitations
-----------
The following options of Wireshark ``dumpcap`` are not yet implemented:

   * ``-f <capture filter>`` -- needs translation from classic BPF to eBPF.

   * ``-b|--ring-buffer`` -- more complex file management.

   * ``-C <byte_limit>`` -- doesn't make sense in DPDK model.

   * ``-t`` -- use a thread per interface

   * Timestamp type.

   * Link data types. Only EN10MB (Ethernet) is supported.

   * Wireless related options:  ``-I|--monitor-mode`` and  ``-k <freq>``


.. Note::
   * The options to ``dpdk-dumpcap`` are like the Wireshark dumpcap program and
     are not the same as ``dpdk-pdump`` and other DPDK applications.
